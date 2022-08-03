// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{cell::RefCell, os::unix::net::UnixStream, path::Path, thread};

use base::{error, Event, RawDescriptor};
use data_model::Le64;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::virtio::{
    vhost::user::vmm::{handler::VhostUserHandler, Error, Result},
    DeviceType, Interrupt, Queue, VirtioDevice,
};

const QUEUE_SIZE: u16 = 1024;
const NUM_QUEUES: usize = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub struct Rng {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<()>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}

impl Rng {
    pub fn new<P: AsRef<Path>>(base_features: u64, socket_path: P) -> Result<Rng> {
        let socket = UnixStream::connect(socket_path).map_err(Error::SocketConnect)?;

        let init_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_features = init_features | base_features;
        let allow_protocol_features =
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;

        let mut handler = VhostUserHandler::new_from_stream(
            socket,
            QUEUE_SIZES.len() as u64,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;
        let queue_sizes = handler.queue_sizes(QUEUE_SIZE, QUEUE_SIZES.len())?;

        Ok(Rng {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl VirtioDevice for Rng {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn features(&self) -> u64 {
        self.handler.borrow().avail_features
    }

    fn ack_features(&mut self, features: u64) {
        if let Err(e) = self.handler.borrow_mut().ack_features(features) {
            error!("failed to enable features 0x{:x}: {}", features, e);
        }
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Rng
    }

    fn queue_max_sizes(&self) -> &[u16] {
        self.queue_sizes.as_slice()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Err(e) = self.handler.borrow_mut().read_config::<Le64>(offset, data) {
            error!("failed to read config: {}", e);
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) {
        match self
            .handler
            .borrow_mut()
            .activate(mem, interrupt, queues, queue_evts, "rng")
        {
            Ok((join_handle, kill_evt)) => {
                self.worker_thread = Some(join_handle);
                self.kill_evt = Some(kill_evt);
            }
            Err(e) => {
                error!("failed to activate queues: {}", e);
            }
        }
    }

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset rng device: {}", e);
            false
        } else {
            true
        }
    }
}
