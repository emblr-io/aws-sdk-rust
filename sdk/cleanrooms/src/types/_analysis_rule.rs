// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A specification about how data from the configured table can be used in a query.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalysisRule {
    /// <p>The unique ID for the associated collaboration.</p>
    pub collaboration_id: ::std::string::String,
    /// <p>The type of analysis rule.</p>
    pub r#type: crate::types::AnalysisRuleType,
    /// <p>The name for the analysis rule.</p>
    pub name: ::std::string::String,
    /// <p>The time the analysis rule was created.</p>
    pub create_time: ::aws_smithy_types::DateTime,
    /// <p>The time the analysis rule was last updated.</p>
    pub update_time: ::aws_smithy_types::DateTime,
    /// <p>A policy that describes the associated data usage limitations.</p>
    pub policy: ::std::option::Option<crate::types::AnalysisRulePolicy>,
    /// <p>Controls on the query specifications that can be run on an associated configured table.</p>
    pub collaboration_policy: ::std::option::Option<crate::types::ConfiguredTableAssociationAnalysisRulePolicy>,
    /// <p>The consolidated policy for the analysis rule.</p>
    pub consolidated_policy: ::std::option::Option<crate::types::ConsolidatedPolicy>,
}
impl AnalysisRule {
    /// <p>The unique ID for the associated collaboration.</p>
    pub fn collaboration_id(&self) -> &str {
        use std::ops::Deref;
        self.collaboration_id.deref()
    }
    /// <p>The type of analysis rule.</p>
    pub fn r#type(&self) -> &crate::types::AnalysisRuleType {
        &self.r#type
    }
    /// <p>The name for the analysis rule.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The time the analysis rule was created.</p>
    pub fn create_time(&self) -> &::aws_smithy_types::DateTime {
        &self.create_time
    }
    /// <p>The time the analysis rule was last updated.</p>
    pub fn update_time(&self) -> &::aws_smithy_types::DateTime {
        &self.update_time
    }
    /// <p>A policy that describes the associated data usage limitations.</p>
    pub fn policy(&self) -> ::std::option::Option<&crate::types::AnalysisRulePolicy> {
        self.policy.as_ref()
    }
    /// <p>Controls on the query specifications that can be run on an associated configured table.</p>
    pub fn collaboration_policy(&self) -> ::std::option::Option<&crate::types::ConfiguredTableAssociationAnalysisRulePolicy> {
        self.collaboration_policy.as_ref()
    }
    /// <p>The consolidated policy for the analysis rule.</p>
    pub fn consolidated_policy(&self) -> ::std::option::Option<&crate::types::ConsolidatedPolicy> {
        self.consolidated_policy.as_ref()
    }
}
impl AnalysisRule {
    /// Creates a new builder-style object to manufacture [`AnalysisRule`](crate::types::AnalysisRule).
    pub fn builder() -> crate::types::builders::AnalysisRuleBuilder {
        crate::types::builders::AnalysisRuleBuilder::default()
    }
}

/// A builder for [`AnalysisRule`](crate::types::AnalysisRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalysisRuleBuilder {
    pub(crate) collaboration_id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::AnalysisRuleType>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) policy: ::std::option::Option<crate::types::AnalysisRulePolicy>,
    pub(crate) collaboration_policy: ::std::option::Option<crate::types::ConfiguredTableAssociationAnalysisRulePolicy>,
    pub(crate) consolidated_policy: ::std::option::Option<crate::types::ConsolidatedPolicy>,
}
impl AnalysisRuleBuilder {
    /// <p>The unique ID for the associated collaboration.</p>
    /// This field is required.
    pub fn collaboration_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collaboration_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for the associated collaboration.</p>
    pub fn set_collaboration_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collaboration_id = input;
        self
    }
    /// <p>The unique ID for the associated collaboration.</p>
    pub fn get_collaboration_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.collaboration_id
    }
    /// <p>The type of analysis rule.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::AnalysisRuleType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of analysis rule.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::AnalysisRuleType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of analysis rule.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::AnalysisRuleType> {
        &self.r#type
    }
    /// <p>The name for the analysis rule.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the analysis rule.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name for the analysis rule.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The time the analysis rule was created.</p>
    /// This field is required.
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the analysis rule was created.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time the analysis rule was created.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The time the analysis rule was last updated.</p>
    /// This field is required.
    pub fn update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the analysis rule was last updated.</p>
    pub fn set_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_time = input;
        self
    }
    /// <p>The time the analysis rule was last updated.</p>
    pub fn get_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_time
    }
    /// <p>A policy that describes the associated data usage limitations.</p>
    /// This field is required.
    pub fn policy(mut self, input: crate::types::AnalysisRulePolicy) -> Self {
        self.policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>A policy that describes the associated data usage limitations.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<crate::types::AnalysisRulePolicy>) -> Self {
        self.policy = input;
        self
    }
    /// <p>A policy that describes the associated data usage limitations.</p>
    pub fn get_policy(&self) -> &::std::option::Option<crate::types::AnalysisRulePolicy> {
        &self.policy
    }
    /// <p>Controls on the query specifications that can be run on an associated configured table.</p>
    pub fn collaboration_policy(mut self, input: crate::types::ConfiguredTableAssociationAnalysisRulePolicy) -> Self {
        self.collaboration_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Controls on the query specifications that can be run on an associated configured table.</p>
    pub fn set_collaboration_policy(mut self, input: ::std::option::Option<crate::types::ConfiguredTableAssociationAnalysisRulePolicy>) -> Self {
        self.collaboration_policy = input;
        self
    }
    /// <p>Controls on the query specifications that can be run on an associated configured table.</p>
    pub fn get_collaboration_policy(&self) -> &::std::option::Option<crate::types::ConfiguredTableAssociationAnalysisRulePolicy> {
        &self.collaboration_policy
    }
    /// <p>The consolidated policy for the analysis rule.</p>
    pub fn consolidated_policy(mut self, input: crate::types::ConsolidatedPolicy) -> Self {
        self.consolidated_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The consolidated policy for the analysis rule.</p>
    pub fn set_consolidated_policy(mut self, input: ::std::option::Option<crate::types::ConsolidatedPolicy>) -> Self {
        self.consolidated_policy = input;
        self
    }
    /// <p>The consolidated policy for the analysis rule.</p>
    pub fn get_consolidated_policy(&self) -> &::std::option::Option<crate::types::ConsolidatedPolicy> {
        &self.consolidated_policy
    }
    /// Consumes the builder and constructs a [`AnalysisRule`](crate::types::AnalysisRule).
    /// This method will fail if any of the following fields are not set:
    /// - [`collaboration_id`](crate::types::builders::AnalysisRuleBuilder::collaboration_id)
    /// - [`r#type`](crate::types::builders::AnalysisRuleBuilder::type)
    /// - [`name`](crate::types::builders::AnalysisRuleBuilder::name)
    /// - [`create_time`](crate::types::builders::AnalysisRuleBuilder::create_time)
    /// - [`update_time`](crate::types::builders::AnalysisRuleBuilder::update_time)
    pub fn build(self) -> ::std::result::Result<crate::types::AnalysisRule, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnalysisRule {
            collaboration_id: self.collaboration_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "collaboration_id",
                    "collaboration_id was not specified but it is required when building AnalysisRule",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building AnalysisRule",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AnalysisRule",
                )
            })?,
            create_time: self.create_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "create_time",
                    "create_time was not specified but it is required when building AnalysisRule",
                )
            })?,
            update_time: self.update_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "update_time",
                    "update_time was not specified but it is required when building AnalysisRule",
                )
            })?,
            policy: self.policy,
            collaboration_policy: self.collaboration_policy,
            consolidated_policy: self.consolidated_policy,
        })
    }
}
