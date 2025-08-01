// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestoreKeyOutput {
    /// <p>The key material of the restored key. The <code>KeyState</code> will change to <code>CREATE_COMPLETE</code> and value for <code>DeletePendingTimestamp</code> gets removed.</p>
    pub key: ::std::option::Option<crate::types::Key>,
    _request_id: Option<String>,
}
impl RestoreKeyOutput {
    /// <p>The key material of the restored key. The <code>KeyState</code> will change to <code>CREATE_COMPLETE</code> and value for <code>DeletePendingTimestamp</code> gets removed.</p>
    pub fn key(&self) -> ::std::option::Option<&crate::types::Key> {
        self.key.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for RestoreKeyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RestoreKeyOutput {
    /// Creates a new builder-style object to manufacture [`RestoreKeyOutput`](crate::operation::restore_key::RestoreKeyOutput).
    pub fn builder() -> crate::operation::restore_key::builders::RestoreKeyOutputBuilder {
        crate::operation::restore_key::builders::RestoreKeyOutputBuilder::default()
    }
}

/// A builder for [`RestoreKeyOutput`](crate::operation::restore_key::RestoreKeyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RestoreKeyOutputBuilder {
    pub(crate) key: ::std::option::Option<crate::types::Key>,
    _request_id: Option<String>,
}
impl RestoreKeyOutputBuilder {
    /// <p>The key material of the restored key. The <code>KeyState</code> will change to <code>CREATE_COMPLETE</code> and value for <code>DeletePendingTimestamp</code> gets removed.</p>
    /// This field is required.
    pub fn key(mut self, input: crate::types::Key) -> Self {
        self.key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The key material of the restored key. The <code>KeyState</code> will change to <code>CREATE_COMPLETE</code> and value for <code>DeletePendingTimestamp</code> gets removed.</p>
    pub fn set_key(mut self, input: ::std::option::Option<crate::types::Key>) -> Self {
        self.key = input;
        self
    }
    /// <p>The key material of the restored key. The <code>KeyState</code> will change to <code>CREATE_COMPLETE</code> and value for <code>DeletePendingTimestamp</code> gets removed.</p>
    pub fn get_key(&self) -> &::std::option::Option<crate::types::Key> {
        &self.key
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RestoreKeyOutput`](crate::operation::restore_key::RestoreKeyOutput).
    pub fn build(self) -> crate::operation::restore_key::RestoreKeyOutput {
        crate::operation::restore_key::RestoreKeyOutput {
            key: self.key,
            _request_id: self._request_id,
        }
    }
}
