use kadmin_sys::*;

use crate::kadmin::KAdmin;

#[derive(Debug)]
pub struct Principal<'a> {
    pub(crate) kadmin: &'a KAdmin,
    pub(crate) inner: _kadm5_principal_ent_t,
}

impl<'a> Principal<'a> {
    pub(crate) fn new(kadmin: &'a KAdmin) -> Self {
        Self {
            kadmin,
            inner: _kadm5_principal_ent_t::default(),
        }
    }
}

impl Drop for Principal<'_> {
    fn drop(&mut self) {
        unsafe {
            kadm5_free_principal_ent(self.kadmin.server_handle, &mut self.inner);
        }
    }
}
