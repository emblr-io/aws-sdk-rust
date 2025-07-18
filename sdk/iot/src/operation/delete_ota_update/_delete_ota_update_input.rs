// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteOtaUpdateInput {
    /// <p>The ID of the OTA update to delete.</p>
    pub ota_update_id: ::std::option::Option<::std::string::String>,
    /// <p>When true, the stream created by the OTAUpdate process is deleted when the OTA update is deleted. Ignored if the stream specified in the OTAUpdate is supplied by the user.</p>
    pub delete_stream: ::std::option::Option<bool>,
    /// <p>When true, deletes the IoT job created by the OTAUpdate process even if it is "IN_PROGRESS". Otherwise, if the job is not in a terminal state ("COMPLETED" or "CANCELED") an exception will occur. The default is false.</p>
    pub force_delete_aws_job: ::std::option::Option<bool>,
}
impl DeleteOtaUpdateInput {
    /// <p>The ID of the OTA update to delete.</p>
    pub fn ota_update_id(&self) -> ::std::option::Option<&str> {
        self.ota_update_id.as_deref()
    }
    /// <p>When true, the stream created by the OTAUpdate process is deleted when the OTA update is deleted. Ignored if the stream specified in the OTAUpdate is supplied by the user.</p>
    pub fn delete_stream(&self) -> ::std::option::Option<bool> {
        self.delete_stream
    }
    /// <p>When true, deletes the IoT job created by the OTAUpdate process even if it is "IN_PROGRESS". Otherwise, if the job is not in a terminal state ("COMPLETED" or "CANCELED") an exception will occur. The default is false.</p>
    pub fn force_delete_aws_job(&self) -> ::std::option::Option<bool> {
        self.force_delete_aws_job
    }
}
impl DeleteOtaUpdateInput {
    /// Creates a new builder-style object to manufacture [`DeleteOtaUpdateInput`](crate::operation::delete_ota_update::DeleteOtaUpdateInput).
    pub fn builder() -> crate::operation::delete_ota_update::builders::DeleteOtaUpdateInputBuilder {
        crate::operation::delete_ota_update::builders::DeleteOtaUpdateInputBuilder::default()
    }
}

/// A builder for [`DeleteOtaUpdateInput`](crate::operation::delete_ota_update::DeleteOtaUpdateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteOtaUpdateInputBuilder {
    pub(crate) ota_update_id: ::std::option::Option<::std::string::String>,
    pub(crate) delete_stream: ::std::option::Option<bool>,
    pub(crate) force_delete_aws_job: ::std::option::Option<bool>,
}
impl DeleteOtaUpdateInputBuilder {
    /// <p>The ID of the OTA update to delete.</p>
    /// This field is required.
    pub fn ota_update_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ota_update_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the OTA update to delete.</p>
    pub fn set_ota_update_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ota_update_id = input;
        self
    }
    /// <p>The ID of the OTA update to delete.</p>
    pub fn get_ota_update_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ota_update_id
    }
    /// <p>When true, the stream created by the OTAUpdate process is deleted when the OTA update is deleted. Ignored if the stream specified in the OTAUpdate is supplied by the user.</p>
    pub fn delete_stream(mut self, input: bool) -> Self {
        self.delete_stream = ::std::option::Option::Some(input);
        self
    }
    /// <p>When true, the stream created by the OTAUpdate process is deleted when the OTA update is deleted. Ignored if the stream specified in the OTAUpdate is supplied by the user.</p>
    pub fn set_delete_stream(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_stream = input;
        self
    }
    /// <p>When true, the stream created by the OTAUpdate process is deleted when the OTA update is deleted. Ignored if the stream specified in the OTAUpdate is supplied by the user.</p>
    pub fn get_delete_stream(&self) -> &::std::option::Option<bool> {
        &self.delete_stream
    }
    /// <p>When true, deletes the IoT job created by the OTAUpdate process even if it is "IN_PROGRESS". Otherwise, if the job is not in a terminal state ("COMPLETED" or "CANCELED") an exception will occur. The default is false.</p>
    pub fn force_delete_aws_job(mut self, input: bool) -> Self {
        self.force_delete_aws_job = ::std::option::Option::Some(input);
        self
    }
    /// <p>When true, deletes the IoT job created by the OTAUpdate process even if it is "IN_PROGRESS". Otherwise, if the job is not in a terminal state ("COMPLETED" or "CANCELED") an exception will occur. The default is false.</p>
    pub fn set_force_delete_aws_job(mut self, input: ::std::option::Option<bool>) -> Self {
        self.force_delete_aws_job = input;
        self
    }
    /// <p>When true, deletes the IoT job created by the OTAUpdate process even if it is "IN_PROGRESS". Otherwise, if the job is not in a terminal state ("COMPLETED" or "CANCELED") an exception will occur. The default is false.</p>
    pub fn get_force_delete_aws_job(&self) -> &::std::option::Option<bool> {
        &self.force_delete_aws_job
    }
    /// Consumes the builder and constructs a [`DeleteOtaUpdateInput`](crate::operation::delete_ota_update::DeleteOtaUpdateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_ota_update::DeleteOtaUpdateInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_ota_update::DeleteOtaUpdateInput {
            ota_update_id: self.ota_update_id,
            delete_stream: self.delete_stream,
            force_delete_aws_job: self.force_delete_aws_job,
        })
    }
}
