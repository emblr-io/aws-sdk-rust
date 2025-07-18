// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The amount of ephemeral storage to allocate for the task.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskEphemeralStorage {
    /// <p>The total amount, in GiB, of the ephemeral storage to set for the task. The minimum supported value is <code>20</code> GiB and the maximum supported value is  <code>200</code> GiB.</p>
    pub size_in_gib: i32,
    /// <p>Specify an Key Management Service key ID to encrypt the ephemeral storage for the task.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
}
impl TaskEphemeralStorage {
    /// <p>The total amount, in GiB, of the ephemeral storage to set for the task. The minimum supported value is <code>20</code> GiB and the maximum supported value is  <code>200</code> GiB.</p>
    pub fn size_in_gib(&self) -> i32 {
        self.size_in_gib
    }
    /// <p>Specify an Key Management Service key ID to encrypt the ephemeral storage for the task.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
}
impl TaskEphemeralStorage {
    /// Creates a new builder-style object to manufacture [`TaskEphemeralStorage`](crate::types::TaskEphemeralStorage).
    pub fn builder() -> crate::types::builders::TaskEphemeralStorageBuilder {
        crate::types::builders::TaskEphemeralStorageBuilder::default()
    }
}

/// A builder for [`TaskEphemeralStorage`](crate::types::TaskEphemeralStorage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskEphemeralStorageBuilder {
    pub(crate) size_in_gib: ::std::option::Option<i32>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
}
impl TaskEphemeralStorageBuilder {
    /// <p>The total amount, in GiB, of the ephemeral storage to set for the task. The minimum supported value is <code>20</code> GiB and the maximum supported value is  <code>200</code> GiB.</p>
    pub fn size_in_gib(mut self, input: i32) -> Self {
        self.size_in_gib = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total amount, in GiB, of the ephemeral storage to set for the task. The minimum supported value is <code>20</code> GiB and the maximum supported value is  <code>200</code> GiB.</p>
    pub fn set_size_in_gib(mut self, input: ::std::option::Option<i32>) -> Self {
        self.size_in_gib = input;
        self
    }
    /// <p>The total amount, in GiB, of the ephemeral storage to set for the task. The minimum supported value is <code>20</code> GiB and the maximum supported value is  <code>200</code> GiB.</p>
    pub fn get_size_in_gib(&self) -> &::std::option::Option<i32> {
        &self.size_in_gib
    }
    /// <p>Specify an Key Management Service key ID to encrypt the ephemeral storage for the task.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify an Key Management Service key ID to encrypt the ephemeral storage for the task.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>Specify an Key Management Service key ID to encrypt the ephemeral storage for the task.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Consumes the builder and constructs a [`TaskEphemeralStorage`](crate::types::TaskEphemeralStorage).
    pub fn build(self) -> crate::types::TaskEphemeralStorage {
        crate::types::TaskEphemeralStorage {
            size_in_gib: self.size_in_gib.unwrap_or_default(),
            kms_key_id: self.kms_key_id,
        }
    }
}
