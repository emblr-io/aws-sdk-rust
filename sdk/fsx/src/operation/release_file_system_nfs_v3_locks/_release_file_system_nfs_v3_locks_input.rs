// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReleaseFileSystemNfsV3LocksInput {
    /// <p>The globally unique ID of the file system, assigned by Amazon FSx.</p>
    pub file_system_id: ::std::option::Option<::std::string::String>,
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl ReleaseFileSystemNfsV3LocksInput {
    /// <p>The globally unique ID of the file system, assigned by Amazon FSx.</p>
    pub fn file_system_id(&self) -> ::std::option::Option<&str> {
        self.file_system_id.as_deref()
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl ReleaseFileSystemNfsV3LocksInput {
    /// Creates a new builder-style object to manufacture [`ReleaseFileSystemNfsV3LocksInput`](crate::operation::release_file_system_nfs_v3_locks::ReleaseFileSystemNfsV3LocksInput).
    pub fn builder() -> crate::operation::release_file_system_nfs_v3_locks::builders::ReleaseFileSystemNfsV3LocksInputBuilder {
        crate::operation::release_file_system_nfs_v3_locks::builders::ReleaseFileSystemNfsV3LocksInputBuilder::default()
    }
}

/// A builder for [`ReleaseFileSystemNfsV3LocksInput`](crate::operation::release_file_system_nfs_v3_locks::ReleaseFileSystemNfsV3LocksInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReleaseFileSystemNfsV3LocksInputBuilder {
    pub(crate) file_system_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl ReleaseFileSystemNfsV3LocksInputBuilder {
    /// <p>The globally unique ID of the file system, assigned by Amazon FSx.</p>
    /// This field is required.
    pub fn file_system_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The globally unique ID of the file system, assigned by Amazon FSx.</p>
    pub fn set_file_system_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_id = input;
        self
    }
    /// <p>The globally unique ID of the file system, assigned by Amazon FSx.</p>
    pub fn get_file_system_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_id
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`ReleaseFileSystemNfsV3LocksInput`](crate::operation::release_file_system_nfs_v3_locks::ReleaseFileSystemNfsV3LocksInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::release_file_system_nfs_v3_locks::ReleaseFileSystemNfsV3LocksInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::release_file_system_nfs_v3_locks::ReleaseFileSystemNfsV3LocksInput {
            file_system_id: self.file_system_id,
            client_request_token: self.client_request_token,
        })
    }
}
