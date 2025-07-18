// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns information about the latest device job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LatestDeviceJob {
    /// <p>The target version of the device software.</p>
    pub image_version: ::std::option::Option<::std::string::String>,
    /// <p>Status of the latest device job.</p>
    pub status: ::std::option::Option<crate::types::UpdateProgress>,
    /// <p>The job's type.</p>
    pub job_type: ::std::option::Option<crate::types::JobType>,
}
impl LatestDeviceJob {
    /// <p>The target version of the device software.</p>
    pub fn image_version(&self) -> ::std::option::Option<&str> {
        self.image_version.as_deref()
    }
    /// <p>Status of the latest device job.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::UpdateProgress> {
        self.status.as_ref()
    }
    /// <p>The job's type.</p>
    pub fn job_type(&self) -> ::std::option::Option<&crate::types::JobType> {
        self.job_type.as_ref()
    }
}
impl LatestDeviceJob {
    /// Creates a new builder-style object to manufacture [`LatestDeviceJob`](crate::types::LatestDeviceJob).
    pub fn builder() -> crate::types::builders::LatestDeviceJobBuilder {
        crate::types::builders::LatestDeviceJobBuilder::default()
    }
}

/// A builder for [`LatestDeviceJob`](crate::types::LatestDeviceJob).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LatestDeviceJobBuilder {
    pub(crate) image_version: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::UpdateProgress>,
    pub(crate) job_type: ::std::option::Option<crate::types::JobType>,
}
impl LatestDeviceJobBuilder {
    /// <p>The target version of the device software.</p>
    pub fn image_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The target version of the device software.</p>
    pub fn set_image_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_version = input;
        self
    }
    /// <p>The target version of the device software.</p>
    pub fn get_image_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_version
    }
    /// <p>Status of the latest device job.</p>
    pub fn status(mut self, input: crate::types::UpdateProgress) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of the latest device job.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::UpdateProgress>) -> Self {
        self.status = input;
        self
    }
    /// <p>Status of the latest device job.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::UpdateProgress> {
        &self.status
    }
    /// <p>The job's type.</p>
    pub fn job_type(mut self, input: crate::types::JobType) -> Self {
        self.job_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The job's type.</p>
    pub fn set_job_type(mut self, input: ::std::option::Option<crate::types::JobType>) -> Self {
        self.job_type = input;
        self
    }
    /// <p>The job's type.</p>
    pub fn get_job_type(&self) -> &::std::option::Option<crate::types::JobType> {
        &self.job_type
    }
    /// Consumes the builder and constructs a [`LatestDeviceJob`](crate::types::LatestDeviceJob).
    pub fn build(self) -> crate::types::LatestDeviceJob {
        crate::types::LatestDeviceJob {
            image_version: self.image_version,
            status: self.status,
            job_type: self.job_type,
        }
    }
}
