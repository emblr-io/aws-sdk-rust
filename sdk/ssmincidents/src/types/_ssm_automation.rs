// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the Systems Manager automation document that will be used as a runbook during an incident.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SsmAutomation {
    /// <p>The Amazon Resource Name (ARN) of the role that the automation document will assume when running commands.</p>
    pub role_arn: ::std::string::String,
    /// <p>The automation document's name.</p>
    pub document_name: ::std::string::String,
    /// <p>The automation document's version to use when running.</p>
    pub document_version: ::std::option::Option<::std::string::String>,
    /// <p>The account that the automation document will be run in. This can be in either the management account or an application account.</p>
    pub target_account: ::std::option::Option<crate::types::SsmTargetAccount>,
    /// <p>The key-value pair parameters to use when running the automation document.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    /// <p>The key-value pair to resolve dynamic parameter values when processing a Systems Manager Automation runbook.</p>
    pub dynamic_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::DynamicSsmParameterValue>>,
}
impl SsmAutomation {
    /// <p>The Amazon Resource Name (ARN) of the role that the automation document will assume when running commands.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
    /// <p>The automation document's name.</p>
    pub fn document_name(&self) -> &str {
        use std::ops::Deref;
        self.document_name.deref()
    }
    /// <p>The automation document's version to use when running.</p>
    pub fn document_version(&self) -> ::std::option::Option<&str> {
        self.document_version.as_deref()
    }
    /// <p>The account that the automation document will be run in. This can be in either the management account or an application account.</p>
    pub fn target_account(&self) -> ::std::option::Option<&crate::types::SsmTargetAccount> {
        self.target_account.as_ref()
    }
    /// <p>The key-value pair parameters to use when running the automation document.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        self.parameters.as_ref()
    }
    /// <p>The key-value pair to resolve dynamic parameter values when processing a Systems Manager Automation runbook.</p>
    pub fn dynamic_parameters(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::DynamicSsmParameterValue>> {
        self.dynamic_parameters.as_ref()
    }
}
impl SsmAutomation {
    /// Creates a new builder-style object to manufacture [`SsmAutomation`](crate::types::SsmAutomation).
    pub fn builder() -> crate::types::builders::SsmAutomationBuilder {
        crate::types::builders::SsmAutomationBuilder::default()
    }
}

/// A builder for [`SsmAutomation`](crate::types::SsmAutomation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SsmAutomationBuilder {
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) document_name: ::std::option::Option<::std::string::String>,
    pub(crate) document_version: ::std::option::Option<::std::string::String>,
    pub(crate) target_account: ::std::option::Option<crate::types::SsmTargetAccount>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    pub(crate) dynamic_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::DynamicSsmParameterValue>>,
}
impl SsmAutomationBuilder {
    /// <p>The Amazon Resource Name (ARN) of the role that the automation document will assume when running commands.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role that the automation document will assume when running commands.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role that the automation document will assume when running commands.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The automation document's name.</p>
    /// This field is required.
    pub fn document_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The automation document's name.</p>
    pub fn set_document_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_name = input;
        self
    }
    /// <p>The automation document's name.</p>
    pub fn get_document_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_name
    }
    /// <p>The automation document's version to use when running.</p>
    pub fn document_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The automation document's version to use when running.</p>
    pub fn set_document_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_version = input;
        self
    }
    /// <p>The automation document's version to use when running.</p>
    pub fn get_document_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_version
    }
    /// <p>The account that the automation document will be run in. This can be in either the management account or an application account.</p>
    pub fn target_account(mut self, input: crate::types::SsmTargetAccount) -> Self {
        self.target_account = ::std::option::Option::Some(input);
        self
    }
    /// <p>The account that the automation document will be run in. This can be in either the management account or an application account.</p>
    pub fn set_target_account(mut self, input: ::std::option::Option<crate::types::SsmTargetAccount>) -> Self {
        self.target_account = input;
        self
    }
    /// <p>The account that the automation document will be run in. This can be in either the management account or an application account.</p>
    pub fn get_target_account(&self) -> &::std::option::Option<crate::types::SsmTargetAccount> {
        &self.target_account
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The key-value pair parameters to use when running the automation document.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The key-value pair parameters to use when running the automation document.</p>
    pub fn set_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The key-value pair parameters to use when running the automation document.</p>
    pub fn get_parameters(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.parameters
    }
    /// Adds a key-value pair to `dynamic_parameters`.
    ///
    /// To override the contents of this collection use [`set_dynamic_parameters`](Self::set_dynamic_parameters).
    ///
    /// <p>The key-value pair to resolve dynamic parameter values when processing a Systems Manager Automation runbook.</p>
    pub fn dynamic_parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::DynamicSsmParameterValue) -> Self {
        let mut hash_map = self.dynamic_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.dynamic_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The key-value pair to resolve dynamic parameter values when processing a Systems Manager Automation runbook.</p>
    pub fn set_dynamic_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::DynamicSsmParameterValue>>,
    ) -> Self {
        self.dynamic_parameters = input;
        self
    }
    /// <p>The key-value pair to resolve dynamic parameter values when processing a Systems Manager Automation runbook.</p>
    pub fn get_dynamic_parameters(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::DynamicSsmParameterValue>> {
        &self.dynamic_parameters
    }
    /// Consumes the builder and constructs a [`SsmAutomation`](crate::types::SsmAutomation).
    /// This method will fail if any of the following fields are not set:
    /// - [`role_arn`](crate::types::builders::SsmAutomationBuilder::role_arn)
    /// - [`document_name`](crate::types::builders::SsmAutomationBuilder::document_name)
    pub fn build(self) -> ::std::result::Result<crate::types::SsmAutomation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SsmAutomation {
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building SsmAutomation",
                )
            })?,
            document_name: self.document_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "document_name",
                    "document_name was not specified but it is required when building SsmAutomation",
                )
            })?,
            document_version: self.document_version,
            target_account: self.target_account,
            parameters: self.parameters,
            dynamic_parameters: self.dynamic_parameters,
        })
    }
}
