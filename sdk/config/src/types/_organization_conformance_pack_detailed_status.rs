// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Organization conformance pack creation or deletion status in each member account. This includes the name of the conformance pack, the status, error code and error message when the conformance pack creation or deletion failed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OrganizationConformancePackDetailedStatus {
    /// <p>The 12-digit account ID of a member account.</p>
    pub account_id: ::std::string::String,
    /// <p>The name of conformance pack deployed in the member account.</p>
    pub conformance_pack_name: ::std::string::String,
    /// <p>Indicates deployment status for conformance pack in a member account. When management account calls <code>PutOrganizationConformancePack</code> action for the first time, conformance pack status is created in the member account. When management account calls <code>PutOrganizationConformancePack</code> action for the second time, conformance pack status is updated in the member account. Conformance pack status is deleted when the management account deletes <code>OrganizationConformancePack</code> and disables service access for <code>config-multiaccountsetup.amazonaws.com</code>.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_SUCCESSFUL</code> when conformance pack has been created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_IN_PROGRESS</code> when conformance pack is being created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code> when conformance pack creation has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_IN_PROGRESS</code> when conformance pack is being deleted in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_SUCCESSFUL</code> when conformance pack has been deleted in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_SUCCESSFUL</code> when conformance pack has been updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_IN_PROGRESS</code> when conformance pack is being updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// </ul>
    pub status: crate::types::OrganizationResourceDetailedStatus,
    /// <p>An error code that is returned when conformance pack creation or deletion failed in the member account.</p>
    pub error_code: ::std::option::Option<::std::string::String>,
    /// <p>An error message indicating that conformance pack account creation or deletion has failed due to an error in the member account.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of the last status update.</p>
    pub last_update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl OrganizationConformancePackDetailedStatus {
    /// <p>The 12-digit account ID of a member account.</p>
    pub fn account_id(&self) -> &str {
        use std::ops::Deref;
        self.account_id.deref()
    }
    /// <p>The name of conformance pack deployed in the member account.</p>
    pub fn conformance_pack_name(&self) -> &str {
        use std::ops::Deref;
        self.conformance_pack_name.deref()
    }
    /// <p>Indicates deployment status for conformance pack in a member account. When management account calls <code>PutOrganizationConformancePack</code> action for the first time, conformance pack status is created in the member account. When management account calls <code>PutOrganizationConformancePack</code> action for the second time, conformance pack status is updated in the member account. Conformance pack status is deleted when the management account deletes <code>OrganizationConformancePack</code> and disables service access for <code>config-multiaccountsetup.amazonaws.com</code>.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_SUCCESSFUL</code> when conformance pack has been created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_IN_PROGRESS</code> when conformance pack is being created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code> when conformance pack creation has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_IN_PROGRESS</code> when conformance pack is being deleted in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_SUCCESSFUL</code> when conformance pack has been deleted in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_SUCCESSFUL</code> when conformance pack has been updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_IN_PROGRESS</code> when conformance pack is being updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// </ul>
    pub fn status(&self) -> &crate::types::OrganizationResourceDetailedStatus {
        &self.status
    }
    /// <p>An error code that is returned when conformance pack creation or deletion failed in the member account.</p>
    pub fn error_code(&self) -> ::std::option::Option<&str> {
        self.error_code.as_deref()
    }
    /// <p>An error message indicating that conformance pack account creation or deletion has failed due to an error in the member account.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>The timestamp of the last status update.</p>
    pub fn last_update_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_update_time.as_ref()
    }
}
impl OrganizationConformancePackDetailedStatus {
    /// Creates a new builder-style object to manufacture [`OrganizationConformancePackDetailedStatus`](crate::types::OrganizationConformancePackDetailedStatus).
    pub fn builder() -> crate::types::builders::OrganizationConformancePackDetailedStatusBuilder {
        crate::types::builders::OrganizationConformancePackDetailedStatusBuilder::default()
    }
}

/// A builder for [`OrganizationConformancePackDetailedStatus`](crate::types::OrganizationConformancePackDetailedStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OrganizationConformancePackDetailedStatusBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) conformance_pack_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::OrganizationResourceDetailedStatus>,
    pub(crate) error_code: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) last_update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl OrganizationConformancePackDetailedStatusBuilder {
    /// <p>The 12-digit account ID of a member account.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The 12-digit account ID of a member account.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The 12-digit account ID of a member account.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The name of conformance pack deployed in the member account.</p>
    /// This field is required.
    pub fn conformance_pack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conformance_pack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of conformance pack deployed in the member account.</p>
    pub fn set_conformance_pack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conformance_pack_name = input;
        self
    }
    /// <p>The name of conformance pack deployed in the member account.</p>
    pub fn get_conformance_pack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.conformance_pack_name
    }
    /// <p>Indicates deployment status for conformance pack in a member account. When management account calls <code>PutOrganizationConformancePack</code> action for the first time, conformance pack status is created in the member account. When management account calls <code>PutOrganizationConformancePack</code> action for the second time, conformance pack status is updated in the member account. Conformance pack status is deleted when the management account deletes <code>OrganizationConformancePack</code> and disables service access for <code>config-multiaccountsetup.amazonaws.com</code>.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_SUCCESSFUL</code> when conformance pack has been created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_IN_PROGRESS</code> when conformance pack is being created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code> when conformance pack creation has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_IN_PROGRESS</code> when conformance pack is being deleted in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_SUCCESSFUL</code> when conformance pack has been deleted in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_SUCCESSFUL</code> when conformance pack has been updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_IN_PROGRESS</code> when conformance pack is being updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// </ul>
    /// This field is required.
    pub fn status(mut self, input: crate::types::OrganizationResourceDetailedStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates deployment status for conformance pack in a member account. When management account calls <code>PutOrganizationConformancePack</code> action for the first time, conformance pack status is created in the member account. When management account calls <code>PutOrganizationConformancePack</code> action for the second time, conformance pack status is updated in the member account. Conformance pack status is deleted when the management account deletes <code>OrganizationConformancePack</code> and disables service access for <code>config-multiaccountsetup.amazonaws.com</code>.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_SUCCESSFUL</code> when conformance pack has been created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_IN_PROGRESS</code> when conformance pack is being created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code> when conformance pack creation has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_IN_PROGRESS</code> when conformance pack is being deleted in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_SUCCESSFUL</code> when conformance pack has been deleted in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_SUCCESSFUL</code> when conformance pack has been updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_IN_PROGRESS</code> when conformance pack is being updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::OrganizationResourceDetailedStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Indicates deployment status for conformance pack in a member account. When management account calls <code>PutOrganizationConformancePack</code> action for the first time, conformance pack status is created in the member account. When management account calls <code>PutOrganizationConformancePack</code> action for the second time, conformance pack status is updated in the member account. Conformance pack status is deleted when the management account deletes <code>OrganizationConformancePack</code> and disables service access for <code>config-multiaccountsetup.amazonaws.com</code>.</p>
    /// <p>Config sets the state of the conformance pack to:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATE_SUCCESSFUL</code> when conformance pack has been created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_IN_PROGRESS</code> when conformance pack is being created in the member account.</p></li>
    /// <li>
    /// <p><code>CREATE_FAILED</code> when conformance pack creation has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_IN_PROGRESS</code> when conformance pack is being deleted in the member account.</p></li>
    /// <li>
    /// <p><code>DELETE_SUCCESSFUL</code> when conformance pack has been deleted in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_SUCCESSFUL</code> when conformance pack has been updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_IN_PROGRESS</code> when conformance pack is being updated in the member account.</p></li>
    /// <li>
    /// <p><code>UPDATE_FAILED</code> when conformance pack deletion has failed in the member account.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::OrganizationResourceDetailedStatus> {
        &self.status
    }
    /// <p>An error code that is returned when conformance pack creation or deletion failed in the member account.</p>
    pub fn error_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An error code that is returned when conformance pack creation or deletion failed in the member account.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>An error code that is returned when conformance pack creation or deletion failed in the member account.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_code
    }
    /// <p>An error message indicating that conformance pack account creation or deletion has failed due to an error in the member account.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An error message indicating that conformance pack account creation or deletion has failed due to an error in the member account.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>An error message indicating that conformance pack account creation or deletion has failed due to an error in the member account.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>The timestamp of the last status update.</p>
    pub fn last_update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of the last status update.</p>
    pub fn set_last_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_update_time = input;
        self
    }
    /// <p>The timestamp of the last status update.</p>
    pub fn get_last_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_update_time
    }
    /// Consumes the builder and constructs a [`OrganizationConformancePackDetailedStatus`](crate::types::OrganizationConformancePackDetailedStatus).
    /// This method will fail if any of the following fields are not set:
    /// - [`account_id`](crate::types::builders::OrganizationConformancePackDetailedStatusBuilder::account_id)
    /// - [`conformance_pack_name`](crate::types::builders::OrganizationConformancePackDetailedStatusBuilder::conformance_pack_name)
    /// - [`status`](crate::types::builders::OrganizationConformancePackDetailedStatusBuilder::status)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::OrganizationConformancePackDetailedStatus, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OrganizationConformancePackDetailedStatus {
            account_id: self.account_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "account_id",
                    "account_id was not specified but it is required when building OrganizationConformancePackDetailedStatus",
                )
            })?,
            conformance_pack_name: self.conformance_pack_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "conformance_pack_name",
                    "conformance_pack_name was not specified but it is required when building OrganizationConformancePackDetailedStatus",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building OrganizationConformancePackDetailedStatus",
                )
            })?,
            error_code: self.error_code,
            error_message: self.error_message,
            last_update_time: self.last_update_time,
        })
    }
}
