// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartDeclarativePoliciesReportInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The name of the S3 bucket where the report will be saved. The bucket must be in the same Region where the report generation request is made.</p>
    pub s3_bucket: ::std::option::Option<::std::string::String>,
    /// <p>The prefix for your S3 object.</p>
    pub s3_prefix: ::std::option::Option<::std::string::String>,
    /// <p>The root ID, organizational unit ID, or account ID.</p>
    /// <p>Format:</p>
    /// <ul>
    /// <li>
    /// <p>For root: <code>r-ab12</code></p></li>
    /// <li>
    /// <p>For OU: <code>ou-ab12-cdef1234</code></p></li>
    /// <li>
    /// <p>For account: <code>123456789012</code></p></li>
    /// </ul>
    pub target_id: ::std::option::Option<::std::string::String>,
    /// <p>The tags to apply.</p>
    pub tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
}
impl StartDeclarativePoliciesReportInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The name of the S3 bucket where the report will be saved. The bucket must be in the same Region where the report generation request is made.</p>
    pub fn s3_bucket(&self) -> ::std::option::Option<&str> {
        self.s3_bucket.as_deref()
    }
    /// <p>The prefix for your S3 object.</p>
    pub fn s3_prefix(&self) -> ::std::option::Option<&str> {
        self.s3_prefix.as_deref()
    }
    /// <p>The root ID, organizational unit ID, or account ID.</p>
    /// <p>Format:</p>
    /// <ul>
    /// <li>
    /// <p>For root: <code>r-ab12</code></p></li>
    /// <li>
    /// <p>For OU: <code>ou-ab12-cdef1234</code></p></li>
    /// <li>
    /// <p>For account: <code>123456789012</code></p></li>
    /// </ul>
    pub fn target_id(&self) -> ::std::option::Option<&str> {
        self.target_id.as_deref()
    }
    /// <p>The tags to apply.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_specifications.is_none()`.
    pub fn tag_specifications(&self) -> &[crate::types::TagSpecification] {
        self.tag_specifications.as_deref().unwrap_or_default()
    }
}
impl StartDeclarativePoliciesReportInput {
    /// Creates a new builder-style object to manufacture [`StartDeclarativePoliciesReportInput`](crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportInput).
    pub fn builder() -> crate::operation::start_declarative_policies_report::builders::StartDeclarativePoliciesReportInputBuilder {
        crate::operation::start_declarative_policies_report::builders::StartDeclarativePoliciesReportInputBuilder::default()
    }
}

/// A builder for [`StartDeclarativePoliciesReportInput`](crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartDeclarativePoliciesReportInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) s3_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) s3_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) target_id: ::std::option::Option<::std::string::String>,
    pub(crate) tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
}
impl StartDeclarativePoliciesReportInputBuilder {
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
    /// <p>The name of the S3 bucket where the report will be saved. The bucket must be in the same Region where the report generation request is made.</p>
    /// This field is required.
    pub fn s3_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the S3 bucket where the report will be saved. The bucket must be in the same Region where the report generation request is made.</p>
    pub fn set_s3_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket = input;
        self
    }
    /// <p>The name of the S3 bucket where the report will be saved. The bucket must be in the same Region where the report generation request is made.</p>
    pub fn get_s3_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket
    }
    /// <p>The prefix for your S3 object.</p>
    pub fn s3_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prefix for your S3 object.</p>
    pub fn set_s3_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_prefix = input;
        self
    }
    /// <p>The prefix for your S3 object.</p>
    pub fn get_s3_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_prefix
    }
    /// <p>The root ID, organizational unit ID, or account ID.</p>
    /// <p>Format:</p>
    /// <ul>
    /// <li>
    /// <p>For root: <code>r-ab12</code></p></li>
    /// <li>
    /// <p>For OU: <code>ou-ab12-cdef1234</code></p></li>
    /// <li>
    /// <p>For account: <code>123456789012</code></p></li>
    /// </ul>
    /// This field is required.
    pub fn target_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The root ID, organizational unit ID, or account ID.</p>
    /// <p>Format:</p>
    /// <ul>
    /// <li>
    /// <p>For root: <code>r-ab12</code></p></li>
    /// <li>
    /// <p>For OU: <code>ou-ab12-cdef1234</code></p></li>
    /// <li>
    /// <p>For account: <code>123456789012</code></p></li>
    /// </ul>
    pub fn set_target_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_id = input;
        self
    }
    /// <p>The root ID, organizational unit ID, or account ID.</p>
    /// <p>Format:</p>
    /// <ul>
    /// <li>
    /// <p>For root: <code>r-ab12</code></p></li>
    /// <li>
    /// <p>For OU: <code>ou-ab12-cdef1234</code></p></li>
    /// <li>
    /// <p>For account: <code>123456789012</code></p></li>
    /// </ul>
    pub fn get_target_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_id
    }
    /// Appends an item to `tag_specifications`.
    ///
    /// To override the contents of this collection use [`set_tag_specifications`](Self::set_tag_specifications).
    ///
    /// <p>The tags to apply.</p>
    pub fn tag_specifications(mut self, input: crate::types::TagSpecification) -> Self {
        let mut v = self.tag_specifications.unwrap_or_default();
        v.push(input);
        self.tag_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to apply.</p>
    pub fn set_tag_specifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>) -> Self {
        self.tag_specifications = input;
        self
    }
    /// <p>The tags to apply.</p>
    pub fn get_tag_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>> {
        &self.tag_specifications
    }
    /// Consumes the builder and constructs a [`StartDeclarativePoliciesReportInput`](crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportInput {
            dry_run: self.dry_run,
            s3_bucket: self.s3_bucket,
            s3_prefix: self.s3_prefix,
            target_id: self.target_id,
            tag_specifications: self.tag_specifications,
        })
    }
}
