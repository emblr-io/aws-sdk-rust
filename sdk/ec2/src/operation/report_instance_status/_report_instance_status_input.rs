// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ReportInstanceStatusInput {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The instances.</p>
    pub instances: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The status of all instances listed.</p>
    pub status: ::std::option::Option<crate::types::ReportStatusType>,
    /// <p>The time at which the reported instance health state began.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time at which the reported instance health state ended.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The reason codes that describe the health state of your instance.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-stuck-in-state</code>: My instance is stuck in a state.</p></li>
    /// <li>
    /// <p><code>unresponsive</code>: My instance is unresponsive.</p></li>
    /// <li>
    /// <p><code>not-accepting-credentials</code>: My instance is not accepting my credentials.</p></li>
    /// <li>
    /// <p><code>password-not-available</code>: A password is not available for my instance.</p></li>
    /// <li>
    /// <p><code>performance-network</code>: My instance is experiencing performance problems that I believe are network related.</p></li>
    /// <li>
    /// <p><code>performance-instance-store</code>: My instance is experiencing performance problems that I believe are related to the instance stores.</p></li>
    /// <li>
    /// <p><code>performance-ebs-volume</code>: My instance is experiencing performance problems that I believe are related to an EBS volume.</p></li>
    /// <li>
    /// <p><code>performance-other</code>: My instance is experiencing performance problems.</p></li>
    /// <li>
    /// <p>other: \[explain using the description parameter\]</p></li>
    /// </ul>
    pub reason_codes: ::std::option::Option<::std::vec::Vec<crate::types::ReportInstanceReasonCodes>>,
    /// <p>Descriptive text about the health state of your instance.</p>
    #[deprecated(note = "This member has been deprecated")]
    pub description: ::std::option::Option<::std::string::String>,
}
impl ReportInstanceStatusInput {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instances.is_none()`.
    pub fn instances(&self) -> &[::std::string::String] {
        self.instances.as_deref().unwrap_or_default()
    }
    /// <p>The status of all instances listed.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ReportStatusType> {
        self.status.as_ref()
    }
    /// <p>The time at which the reported instance health state began.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The time at which the reported instance health state ended.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The reason codes that describe the health state of your instance.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-stuck-in-state</code>: My instance is stuck in a state.</p></li>
    /// <li>
    /// <p><code>unresponsive</code>: My instance is unresponsive.</p></li>
    /// <li>
    /// <p><code>not-accepting-credentials</code>: My instance is not accepting my credentials.</p></li>
    /// <li>
    /// <p><code>password-not-available</code>: A password is not available for my instance.</p></li>
    /// <li>
    /// <p><code>performance-network</code>: My instance is experiencing performance problems that I believe are network related.</p></li>
    /// <li>
    /// <p><code>performance-instance-store</code>: My instance is experiencing performance problems that I believe are related to the instance stores.</p></li>
    /// <li>
    /// <p><code>performance-ebs-volume</code>: My instance is experiencing performance problems that I believe are related to an EBS volume.</p></li>
    /// <li>
    /// <p><code>performance-other</code>: My instance is experiencing performance problems.</p></li>
    /// <li>
    /// <p>other: \[explain using the description parameter\]</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reason_codes.is_none()`.
    pub fn reason_codes(&self) -> &[crate::types::ReportInstanceReasonCodes] {
        self.reason_codes.as_deref().unwrap_or_default()
    }
    /// <p>Descriptive text about the health state of your instance.</p>
    #[deprecated(note = "This member has been deprecated")]
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl ::std::fmt::Debug for ReportInstanceStatusInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ReportInstanceStatusInput");
        formatter.field("dry_run", &self.dry_run);
        formatter.field("instances", &self.instances);
        formatter.field("status", &self.status);
        formatter.field("start_time", &self.start_time);
        formatter.field("end_time", &self.end_time);
        formatter.field("reason_codes", &self.reason_codes);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl ReportInstanceStatusInput {
    /// Creates a new builder-style object to manufacture [`ReportInstanceStatusInput`](crate::operation::report_instance_status::ReportInstanceStatusInput).
    pub fn builder() -> crate::operation::report_instance_status::builders::ReportInstanceStatusInputBuilder {
        crate::operation::report_instance_status::builders::ReportInstanceStatusInputBuilder::default()
    }
}

/// A builder for [`ReportInstanceStatusInput`](crate::operation::report_instance_status::ReportInstanceStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ReportInstanceStatusInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) instances: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) status: ::std::option::Option<crate::types::ReportStatusType>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) reason_codes: ::std::option::Option<::std::vec::Vec<crate::types::ReportInstanceReasonCodes>>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl ReportInstanceStatusInputBuilder {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Appends an item to `instances`.
    ///
    /// To override the contents of this collection use [`set_instances`](Self::set_instances).
    ///
    /// <p>The instances.</p>
    pub fn instances(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instances.unwrap_or_default();
        v.push(input.into());
        self.instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>The instances.</p>
    pub fn set_instances(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instances = input;
        self
    }
    /// <p>The instances.</p>
    pub fn get_instances(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instances
    }
    /// <p>The status of all instances listed.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::ReportStatusType) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of all instances listed.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ReportStatusType>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of all instances listed.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ReportStatusType> {
        &self.status
    }
    /// <p>The time at which the reported instance health state began.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the reported instance health state began.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The time at which the reported instance health state began.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The time at which the reported instance health state ended.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the reported instance health state ended.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The time at which the reported instance health state ended.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Appends an item to `reason_codes`.
    ///
    /// To override the contents of this collection use [`set_reason_codes`](Self::set_reason_codes).
    ///
    /// <p>The reason codes that describe the health state of your instance.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-stuck-in-state</code>: My instance is stuck in a state.</p></li>
    /// <li>
    /// <p><code>unresponsive</code>: My instance is unresponsive.</p></li>
    /// <li>
    /// <p><code>not-accepting-credentials</code>: My instance is not accepting my credentials.</p></li>
    /// <li>
    /// <p><code>password-not-available</code>: A password is not available for my instance.</p></li>
    /// <li>
    /// <p><code>performance-network</code>: My instance is experiencing performance problems that I believe are network related.</p></li>
    /// <li>
    /// <p><code>performance-instance-store</code>: My instance is experiencing performance problems that I believe are related to the instance stores.</p></li>
    /// <li>
    /// <p><code>performance-ebs-volume</code>: My instance is experiencing performance problems that I believe are related to an EBS volume.</p></li>
    /// <li>
    /// <p><code>performance-other</code>: My instance is experiencing performance problems.</p></li>
    /// <li>
    /// <p>other: \[explain using the description parameter\]</p></li>
    /// </ul>
    pub fn reason_codes(mut self, input: crate::types::ReportInstanceReasonCodes) -> Self {
        let mut v = self.reason_codes.unwrap_or_default();
        v.push(input);
        self.reason_codes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The reason codes that describe the health state of your instance.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-stuck-in-state</code>: My instance is stuck in a state.</p></li>
    /// <li>
    /// <p><code>unresponsive</code>: My instance is unresponsive.</p></li>
    /// <li>
    /// <p><code>not-accepting-credentials</code>: My instance is not accepting my credentials.</p></li>
    /// <li>
    /// <p><code>password-not-available</code>: A password is not available for my instance.</p></li>
    /// <li>
    /// <p><code>performance-network</code>: My instance is experiencing performance problems that I believe are network related.</p></li>
    /// <li>
    /// <p><code>performance-instance-store</code>: My instance is experiencing performance problems that I believe are related to the instance stores.</p></li>
    /// <li>
    /// <p><code>performance-ebs-volume</code>: My instance is experiencing performance problems that I believe are related to an EBS volume.</p></li>
    /// <li>
    /// <p><code>performance-other</code>: My instance is experiencing performance problems.</p></li>
    /// <li>
    /// <p>other: \[explain using the description parameter\]</p></li>
    /// </ul>
    pub fn set_reason_codes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReportInstanceReasonCodes>>) -> Self {
        self.reason_codes = input;
        self
    }
    /// <p>The reason codes that describe the health state of your instance.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-stuck-in-state</code>: My instance is stuck in a state.</p></li>
    /// <li>
    /// <p><code>unresponsive</code>: My instance is unresponsive.</p></li>
    /// <li>
    /// <p><code>not-accepting-credentials</code>: My instance is not accepting my credentials.</p></li>
    /// <li>
    /// <p><code>password-not-available</code>: A password is not available for my instance.</p></li>
    /// <li>
    /// <p><code>performance-network</code>: My instance is experiencing performance problems that I believe are network related.</p></li>
    /// <li>
    /// <p><code>performance-instance-store</code>: My instance is experiencing performance problems that I believe are related to the instance stores.</p></li>
    /// <li>
    /// <p><code>performance-ebs-volume</code>: My instance is experiencing performance problems that I believe are related to an EBS volume.</p></li>
    /// <li>
    /// <p><code>performance-other</code>: My instance is experiencing performance problems.</p></li>
    /// <li>
    /// <p>other: \[explain using the description parameter\]</p></li>
    /// </ul>
    pub fn get_reason_codes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReportInstanceReasonCodes>> {
        &self.reason_codes
    }
    /// <p>Descriptive text about the health state of your instance.</p>
    #[deprecated(note = "This member has been deprecated")]
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Descriptive text about the health state of your instance.</p>
    #[deprecated(note = "This member has been deprecated")]
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Descriptive text about the health state of your instance.</p>
    #[deprecated(note = "This member has been deprecated")]
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`ReportInstanceStatusInput`](crate::operation::report_instance_status::ReportInstanceStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::report_instance_status::ReportInstanceStatusInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::report_instance_status::ReportInstanceStatusInput {
            dry_run: self.dry_run,
            instances: self.instances,
            status: self.status,
            start_time: self.start_time,
            end_time: self.end_time,
            reason_codes: self.reason_codes,
            description: self.description,
        })
    }
}
impl ::std::fmt::Debug for ReportInstanceStatusInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ReportInstanceStatusInputBuilder");
        formatter.field("dry_run", &self.dry_run);
        formatter.field("instances", &self.instances);
        formatter.field("status", &self.status);
        formatter.field("start_time", &self.start_time);
        formatter.field("end_time", &self.end_time);
        formatter.field("reason_codes", &self.reason_codes);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
