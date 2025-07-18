// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The CIS session message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CisSessionMessage {
    /// <p>The rule ID for the CIS session message.</p>
    pub rule_id: ::std::string::String,
    /// <p>The status of the CIS session message.</p>
    pub status: crate::types::CisRuleStatus,
    /// <p>The CIS rule details for the CIS session message.</p>
    pub cis_rule_details: ::aws_smithy_types::Blob,
}
impl CisSessionMessage {
    /// <p>The rule ID for the CIS session message.</p>
    pub fn rule_id(&self) -> &str {
        use std::ops::Deref;
        self.rule_id.deref()
    }
    /// <p>The status of the CIS session message.</p>
    pub fn status(&self) -> &crate::types::CisRuleStatus {
        &self.status
    }
    /// <p>The CIS rule details for the CIS session message.</p>
    pub fn cis_rule_details(&self) -> &::aws_smithy_types::Blob {
        &self.cis_rule_details
    }
}
impl CisSessionMessage {
    /// Creates a new builder-style object to manufacture [`CisSessionMessage`](crate::types::CisSessionMessage).
    pub fn builder() -> crate::types::builders::CisSessionMessageBuilder {
        crate::types::builders::CisSessionMessageBuilder::default()
    }
}

/// A builder for [`CisSessionMessage`](crate::types::CisSessionMessage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CisSessionMessageBuilder {
    pub(crate) rule_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::CisRuleStatus>,
    pub(crate) cis_rule_details: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl CisSessionMessageBuilder {
    /// <p>The rule ID for the CIS session message.</p>
    /// This field is required.
    pub fn rule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule ID for the CIS session message.</p>
    pub fn set_rule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_id = input;
        self
    }
    /// <p>The rule ID for the CIS session message.</p>
    pub fn get_rule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_id
    }
    /// <p>The status of the CIS session message.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::CisRuleStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the CIS session message.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::CisRuleStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the CIS session message.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::CisRuleStatus> {
        &self.status
    }
    /// <p>The CIS rule details for the CIS session message.</p>
    /// This field is required.
    pub fn cis_rule_details(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.cis_rule_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The CIS rule details for the CIS session message.</p>
    pub fn set_cis_rule_details(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.cis_rule_details = input;
        self
    }
    /// <p>The CIS rule details for the CIS session message.</p>
    pub fn get_cis_rule_details(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.cis_rule_details
    }
    /// Consumes the builder and constructs a [`CisSessionMessage`](crate::types::CisSessionMessage).
    /// This method will fail if any of the following fields are not set:
    /// - [`rule_id`](crate::types::builders::CisSessionMessageBuilder::rule_id)
    /// - [`status`](crate::types::builders::CisSessionMessageBuilder::status)
    /// - [`cis_rule_details`](crate::types::builders::CisSessionMessageBuilder::cis_rule_details)
    pub fn build(self) -> ::std::result::Result<crate::types::CisSessionMessage, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CisSessionMessage {
            rule_id: self.rule_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "rule_id",
                    "rule_id was not specified but it is required when building CisSessionMessage",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building CisSessionMessage",
                )
            })?,
            cis_rule_details: self.cis_rule_details.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "cis_rule_details",
                    "cis_rule_details was not specified but it is required when building CisSessionMessage",
                )
            })?,
        })
    }
}
