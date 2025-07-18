// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportInstanceInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>A description for the instance being imported.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The launch specification.</p>
    pub launch_specification: ::std::option::Option<crate::types::ImportInstanceLaunchSpecification>,
    /// <p>The disk image.</p>
    pub disk_images: ::std::option::Option<::std::vec::Vec<crate::types::DiskImage>>,
    /// <p>The instance operating system.</p>
    pub platform: ::std::option::Option<crate::types::PlatformValues>,
}
impl ImportInstanceInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>A description for the instance being imported.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The launch specification.</p>
    pub fn launch_specification(&self) -> ::std::option::Option<&crate::types::ImportInstanceLaunchSpecification> {
        self.launch_specification.as_ref()
    }
    /// <p>The disk image.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.disk_images.is_none()`.
    pub fn disk_images(&self) -> &[crate::types::DiskImage] {
        self.disk_images.as_deref().unwrap_or_default()
    }
    /// <p>The instance operating system.</p>
    pub fn platform(&self) -> ::std::option::Option<&crate::types::PlatformValues> {
        self.platform.as_ref()
    }
}
impl ImportInstanceInput {
    /// Creates a new builder-style object to manufacture [`ImportInstanceInput`](crate::operation::import_instance::ImportInstanceInput).
    pub fn builder() -> crate::operation::import_instance::builders::ImportInstanceInputBuilder {
        crate::operation::import_instance::builders::ImportInstanceInputBuilder::default()
    }
}

/// A builder for [`ImportInstanceInput`](crate::operation::import_instance::ImportInstanceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportInstanceInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) launch_specification: ::std::option::Option<crate::types::ImportInstanceLaunchSpecification>,
    pub(crate) disk_images: ::std::option::Option<::std::vec::Vec<crate::types::DiskImage>>,
    pub(crate) platform: ::std::option::Option<crate::types::PlatformValues>,
}
impl ImportInstanceInputBuilder {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>A description for the instance being imported.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the instance being imported.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the instance being imported.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The launch specification.</p>
    pub fn launch_specification(mut self, input: crate::types::ImportInstanceLaunchSpecification) -> Self {
        self.launch_specification = ::std::option::Option::Some(input);
        self
    }
    /// <p>The launch specification.</p>
    pub fn set_launch_specification(mut self, input: ::std::option::Option<crate::types::ImportInstanceLaunchSpecification>) -> Self {
        self.launch_specification = input;
        self
    }
    /// <p>The launch specification.</p>
    pub fn get_launch_specification(&self) -> &::std::option::Option<crate::types::ImportInstanceLaunchSpecification> {
        &self.launch_specification
    }
    /// Appends an item to `disk_images`.
    ///
    /// To override the contents of this collection use [`set_disk_images`](Self::set_disk_images).
    ///
    /// <p>The disk image.</p>
    pub fn disk_images(mut self, input: crate::types::DiskImage) -> Self {
        let mut v = self.disk_images.unwrap_or_default();
        v.push(input);
        self.disk_images = ::std::option::Option::Some(v);
        self
    }
    /// <p>The disk image.</p>
    pub fn set_disk_images(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DiskImage>>) -> Self {
        self.disk_images = input;
        self
    }
    /// <p>The disk image.</p>
    pub fn get_disk_images(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DiskImage>> {
        &self.disk_images
    }
    /// <p>The instance operating system.</p>
    /// This field is required.
    pub fn platform(mut self, input: crate::types::PlatformValues) -> Self {
        self.platform = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance operating system.</p>
    pub fn set_platform(mut self, input: ::std::option::Option<crate::types::PlatformValues>) -> Self {
        self.platform = input;
        self
    }
    /// <p>The instance operating system.</p>
    pub fn get_platform(&self) -> &::std::option::Option<crate::types::PlatformValues> {
        &self.platform
    }
    /// Consumes the builder and constructs a [`ImportInstanceInput`](crate::operation::import_instance::ImportInstanceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::import_instance::ImportInstanceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::import_instance::ImportInstanceInput {
            dry_run: self.dry_run,
            description: self.description,
            launch_specification: self.launch_specification,
            disk_images: self.disk_images,
            platform: self.platform,
        })
    }
}
