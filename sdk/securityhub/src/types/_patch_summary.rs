// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides an overview of the patch compliance status for an instance against a selected compliance standard.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PatchSummary {
    /// <p>The identifier of the compliance standard that was used to determine the patch compliance status.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The number of patches from the compliance standard that were installed successfully.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub installed_count: ::std::option::Option<i32>,
    /// <p>The number of patches that are part of the compliance standard but are not installed. The count includes patches that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub missing_count: ::std::option::Option<i32>,
    /// <p>The number of patches from the compliance standard that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub failed_count: ::std::option::Option<i32>,
    /// <p>The number of installed patches that are not part of the compliance standard.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub installed_other_count: ::std::option::Option<i32>,
    /// <p>The number of patches that are installed but are also on a list of patches that the customer rejected.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub installed_rejected_count: ::std::option::Option<i32>,
    /// <p>The number of patches that were applied, but that require the instance to be rebooted in order to be marked as installed.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub installed_pending_reboot: ::std::option::Option<i32>,
    /// <p>Indicates when the operation started.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub operation_start_time: ::std::option::Option<::std::string::String>,
    /// <p>Indicates when the operation completed.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub operation_end_time: ::std::option::Option<::std::string::String>,
    /// <p>The reboot option specified for the instance.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub reboot_option: ::std::option::Option<::std::string::String>,
    /// <p>The type of patch operation performed. For Patch Manager, the values are <code>SCAN</code> and <code>INSTALL</code>.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub operation: ::std::option::Option<::std::string::String>,
}
impl PatchSummary {
    /// <p>The identifier of the compliance standard that was used to determine the patch compliance status.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The number of patches from the compliance standard that were installed successfully.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn installed_count(&self) -> ::std::option::Option<i32> {
        self.installed_count
    }
    /// <p>The number of patches that are part of the compliance standard but are not installed. The count includes patches that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn missing_count(&self) -> ::std::option::Option<i32> {
        self.missing_count
    }
    /// <p>The number of patches from the compliance standard that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn failed_count(&self) -> ::std::option::Option<i32> {
        self.failed_count
    }
    /// <p>The number of installed patches that are not part of the compliance standard.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn installed_other_count(&self) -> ::std::option::Option<i32> {
        self.installed_other_count
    }
    /// <p>The number of patches that are installed but are also on a list of patches that the customer rejected.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn installed_rejected_count(&self) -> ::std::option::Option<i32> {
        self.installed_rejected_count
    }
    /// <p>The number of patches that were applied, but that require the instance to be rebooted in order to be marked as installed.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn installed_pending_reboot(&self) -> ::std::option::Option<i32> {
        self.installed_pending_reboot
    }
    /// <p>Indicates when the operation started.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn operation_start_time(&self) -> ::std::option::Option<&str> {
        self.operation_start_time.as_deref()
    }
    /// <p>Indicates when the operation completed.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn operation_end_time(&self) -> ::std::option::Option<&str> {
        self.operation_end_time.as_deref()
    }
    /// <p>The reboot option specified for the instance.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn reboot_option(&self) -> ::std::option::Option<&str> {
        self.reboot_option.as_deref()
    }
    /// <p>The type of patch operation performed. For Patch Manager, the values are <code>SCAN</code> and <code>INSTALL</code>.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn operation(&self) -> ::std::option::Option<&str> {
        self.operation.as_deref()
    }
}
impl PatchSummary {
    /// Creates a new builder-style object to manufacture [`PatchSummary`](crate::types::PatchSummary).
    pub fn builder() -> crate::types::builders::PatchSummaryBuilder {
        crate::types::builders::PatchSummaryBuilder::default()
    }
}

/// A builder for [`PatchSummary`](crate::types::PatchSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PatchSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) installed_count: ::std::option::Option<i32>,
    pub(crate) missing_count: ::std::option::Option<i32>,
    pub(crate) failed_count: ::std::option::Option<i32>,
    pub(crate) installed_other_count: ::std::option::Option<i32>,
    pub(crate) installed_rejected_count: ::std::option::Option<i32>,
    pub(crate) installed_pending_reboot: ::std::option::Option<i32>,
    pub(crate) operation_start_time: ::std::option::Option<::std::string::String>,
    pub(crate) operation_end_time: ::std::option::Option<::std::string::String>,
    pub(crate) reboot_option: ::std::option::Option<::std::string::String>,
    pub(crate) operation: ::std::option::Option<::std::string::String>,
}
impl PatchSummaryBuilder {
    /// <p>The identifier of the compliance standard that was used to determine the patch compliance status.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the compliance standard that was used to determine the patch compliance status.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the compliance standard that was used to determine the patch compliance status.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The number of patches from the compliance standard that were installed successfully.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn installed_count(mut self, input: i32) -> Self {
        self.installed_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of patches from the compliance standard that were installed successfully.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn set_installed_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.installed_count = input;
        self
    }
    /// <p>The number of patches from the compliance standard that were installed successfully.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn get_installed_count(&self) -> &::std::option::Option<i32> {
        &self.installed_count
    }
    /// <p>The number of patches that are part of the compliance standard but are not installed. The count includes patches that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn missing_count(mut self, input: i32) -> Self {
        self.missing_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of patches that are part of the compliance standard but are not installed. The count includes patches that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn set_missing_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.missing_count = input;
        self
    }
    /// <p>The number of patches that are part of the compliance standard but are not installed. The count includes patches that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn get_missing_count(&self) -> &::std::option::Option<i32> {
        &self.missing_count
    }
    /// <p>The number of patches from the compliance standard that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn failed_count(mut self, input: i32) -> Self {
        self.failed_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of patches from the compliance standard that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn set_failed_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.failed_count = input;
        self
    }
    /// <p>The number of patches from the compliance standard that failed to install.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn get_failed_count(&self) -> &::std::option::Option<i32> {
        &self.failed_count
    }
    /// <p>The number of installed patches that are not part of the compliance standard.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn installed_other_count(mut self, input: i32) -> Self {
        self.installed_other_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of installed patches that are not part of the compliance standard.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn set_installed_other_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.installed_other_count = input;
        self
    }
    /// <p>The number of installed patches that are not part of the compliance standard.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn get_installed_other_count(&self) -> &::std::option::Option<i32> {
        &self.installed_other_count
    }
    /// <p>The number of patches that are installed but are also on a list of patches that the customer rejected.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn installed_rejected_count(mut self, input: i32) -> Self {
        self.installed_rejected_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of patches that are installed but are also on a list of patches that the customer rejected.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn set_installed_rejected_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.installed_rejected_count = input;
        self
    }
    /// <p>The number of patches that are installed but are also on a list of patches that the customer rejected.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn get_installed_rejected_count(&self) -> &::std::option::Option<i32> {
        &self.installed_rejected_count
    }
    /// <p>The number of patches that were applied, but that require the instance to be rebooted in order to be marked as installed.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn installed_pending_reboot(mut self, input: i32) -> Self {
        self.installed_pending_reboot = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of patches that were applied, but that require the instance to be rebooted in order to be marked as installed.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn set_installed_pending_reboot(mut self, input: ::std::option::Option<i32>) -> Self {
        self.installed_pending_reboot = input;
        self
    }
    /// <p>The number of patches that were applied, but that require the instance to be rebooted in order to be marked as installed.</p>
    /// <p>The value can be an integer from <code>0</code> to <code>100000</code>.</p>
    pub fn get_installed_pending_reboot(&self) -> &::std::option::Option<i32> {
        &self.installed_pending_reboot
    }
    /// <p>Indicates when the operation started.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn operation_start_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_start_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates when the operation started.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn set_operation_start_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_start_time = input;
        self
    }
    /// <p>Indicates when the operation started.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn get_operation_start_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_start_time
    }
    /// <p>Indicates when the operation completed.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn operation_end_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_end_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates when the operation completed.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn set_operation_end_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_end_time = input;
        self
    }
    /// <p>Indicates when the operation completed.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn get_operation_end_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_end_time
    }
    /// <p>The reboot option specified for the instance.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn reboot_option(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reboot_option = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reboot option specified for the instance.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn set_reboot_option(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reboot_option = input;
        self
    }
    /// <p>The reboot option specified for the instance.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn get_reboot_option(&self) -> &::std::option::Option<::std::string::String> {
        &self.reboot_option
    }
    /// <p>The type of patch operation performed. For Patch Manager, the values are <code>SCAN</code> and <code>INSTALL</code>.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn operation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of patch operation performed. For Patch Manager, the values are <code>SCAN</code> and <code>INSTALL</code>.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn set_operation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation = input;
        self
    }
    /// <p>The type of patch operation performed. For Patch Manager, the values are <code>SCAN</code> and <code>INSTALL</code>.</p>
    /// <p>Length Constraints: Minimum length of 1. Maximum length of 256.</p>
    pub fn get_operation(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation
    }
    /// Consumes the builder and constructs a [`PatchSummary`](crate::types::PatchSummary).
    pub fn build(self) -> crate::types::PatchSummary {
        crate::types::PatchSummary {
            id: self.id,
            installed_count: self.installed_count,
            missing_count: self.missing_count,
            failed_count: self.failed_count,
            installed_other_count: self.installed_other_count,
            installed_rejected_count: self.installed_rejected_count,
            installed_pending_reboot: self.installed_pending_reboot,
            operation_start_time: self.operation_start_time,
            operation_end_time: self.operation_end_time,
            reboot_option: self.reboot_option,
            operation: self.operation,
        }
    }
}
