// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLocationFsxOpenZfsInput {
    /// <p>Specifies the Amazon Resource Name (ARN) of the FSx for OpenZFS transfer location that you're updating.</p>
    pub location_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the data transfer protocol that DataSync uses to access your Amazon FSx file system.</p>
    pub protocol: ::std::option::Option<crate::types::FsxProtocol>,
    /// <p>Specifies a subdirectory in the location's path that must begin with <code>/fsx</code>. DataSync uses this subdirectory to read or write data (depending on whether the file system is a source or destination location).</p>
    pub subdirectory: ::std::option::Option<::std::string::String>,
}
impl UpdateLocationFsxOpenZfsInput {
    /// <p>Specifies the Amazon Resource Name (ARN) of the FSx for OpenZFS transfer location that you're updating.</p>
    pub fn location_arn(&self) -> ::std::option::Option<&str> {
        self.location_arn.as_deref()
    }
    /// <p>Specifies the data transfer protocol that DataSync uses to access your Amazon FSx file system.</p>
    pub fn protocol(&self) -> ::std::option::Option<&crate::types::FsxProtocol> {
        self.protocol.as_ref()
    }
    /// <p>Specifies a subdirectory in the location's path that must begin with <code>/fsx</code>. DataSync uses this subdirectory to read or write data (depending on whether the file system is a source or destination location).</p>
    pub fn subdirectory(&self) -> ::std::option::Option<&str> {
        self.subdirectory.as_deref()
    }
}
impl UpdateLocationFsxOpenZfsInput {
    /// Creates a new builder-style object to manufacture [`UpdateLocationFsxOpenZfsInput`](crate::operation::update_location_fsx_open_zfs::UpdateLocationFsxOpenZfsInput).
    pub fn builder() -> crate::operation::update_location_fsx_open_zfs::builders::UpdateLocationFsxOpenZfsInputBuilder {
        crate::operation::update_location_fsx_open_zfs::builders::UpdateLocationFsxOpenZfsInputBuilder::default()
    }
}

/// A builder for [`UpdateLocationFsxOpenZfsInput`](crate::operation::update_location_fsx_open_zfs::UpdateLocationFsxOpenZfsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLocationFsxOpenZfsInputBuilder {
    pub(crate) location_arn: ::std::option::Option<::std::string::String>,
    pub(crate) protocol: ::std::option::Option<crate::types::FsxProtocol>,
    pub(crate) subdirectory: ::std::option::Option<::std::string::String>,
}
impl UpdateLocationFsxOpenZfsInputBuilder {
    /// <p>Specifies the Amazon Resource Name (ARN) of the FSx for OpenZFS transfer location that you're updating.</p>
    /// This field is required.
    pub fn location_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the FSx for OpenZFS transfer location that you're updating.</p>
    pub fn set_location_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_arn = input;
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the FSx for OpenZFS transfer location that you're updating.</p>
    pub fn get_location_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_arn
    }
    /// <p>Specifies the data transfer protocol that DataSync uses to access your Amazon FSx file system.</p>
    pub fn protocol(mut self, input: crate::types::FsxProtocol) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the data transfer protocol that DataSync uses to access your Amazon FSx file system.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::FsxProtocol>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>Specifies the data transfer protocol that DataSync uses to access your Amazon FSx file system.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::FsxProtocol> {
        &self.protocol
    }
    /// <p>Specifies a subdirectory in the location's path that must begin with <code>/fsx</code>. DataSync uses this subdirectory to read or write data (depending on whether the file system is a source or destination location).</p>
    pub fn subdirectory(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subdirectory = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a subdirectory in the location's path that must begin with <code>/fsx</code>. DataSync uses this subdirectory to read or write data (depending on whether the file system is a source or destination location).</p>
    pub fn set_subdirectory(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subdirectory = input;
        self
    }
    /// <p>Specifies a subdirectory in the location's path that must begin with <code>/fsx</code>. DataSync uses this subdirectory to read or write data (depending on whether the file system is a source or destination location).</p>
    pub fn get_subdirectory(&self) -> &::std::option::Option<::std::string::String> {
        &self.subdirectory
    }
    /// Consumes the builder and constructs a [`UpdateLocationFsxOpenZfsInput`](crate::operation::update_location_fsx_open_zfs::UpdateLocationFsxOpenZfsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_location_fsx_open_zfs::UpdateLocationFsxOpenZfsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_location_fsx_open_zfs::UpdateLocationFsxOpenZfsInput {
            location_arn: self.location_arn,
            protocol: self.protocol,
            subdirectory: self.subdirectory,
        })
    }
}
