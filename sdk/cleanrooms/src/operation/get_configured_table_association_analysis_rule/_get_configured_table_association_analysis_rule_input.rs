// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConfiguredTableAssociationAnalysisRuleInput {
    /// <p>A unique identifier for the membership that the configured table association belongs to. Currently accepts the membership ID.</p>
    pub membership_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identiﬁer for the conﬁgured table association that's related to the analysis rule.</p>
    pub configured_table_association_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The type of analysis rule that you want to retrieve.</p>
    pub analysis_rule_type: ::std::option::Option<crate::types::ConfiguredTableAssociationAnalysisRuleType>,
}
impl GetConfiguredTableAssociationAnalysisRuleInput {
    /// <p>A unique identifier for the membership that the configured table association belongs to. Currently accepts the membership ID.</p>
    pub fn membership_identifier(&self) -> ::std::option::Option<&str> {
        self.membership_identifier.as_deref()
    }
    /// <p>The identiﬁer for the conﬁgured table association that's related to the analysis rule.</p>
    pub fn configured_table_association_identifier(&self) -> ::std::option::Option<&str> {
        self.configured_table_association_identifier.as_deref()
    }
    /// <p>The type of analysis rule that you want to retrieve.</p>
    pub fn analysis_rule_type(&self) -> ::std::option::Option<&crate::types::ConfiguredTableAssociationAnalysisRuleType> {
        self.analysis_rule_type.as_ref()
    }
}
impl GetConfiguredTableAssociationAnalysisRuleInput {
    /// Creates a new builder-style object to manufacture [`GetConfiguredTableAssociationAnalysisRuleInput`](crate::operation::get_configured_table_association_analysis_rule::GetConfiguredTableAssociationAnalysisRuleInput).
    pub fn builder(
    ) -> crate::operation::get_configured_table_association_analysis_rule::builders::GetConfiguredTableAssociationAnalysisRuleInputBuilder {
        crate::operation::get_configured_table_association_analysis_rule::builders::GetConfiguredTableAssociationAnalysisRuleInputBuilder::default()
    }
}

/// A builder for [`GetConfiguredTableAssociationAnalysisRuleInput`](crate::operation::get_configured_table_association_analysis_rule::GetConfiguredTableAssociationAnalysisRuleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConfiguredTableAssociationAnalysisRuleInputBuilder {
    pub(crate) membership_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) configured_table_association_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) analysis_rule_type: ::std::option::Option<crate::types::ConfiguredTableAssociationAnalysisRuleType>,
}
impl GetConfiguredTableAssociationAnalysisRuleInputBuilder {
    /// <p>A unique identifier for the membership that the configured table association belongs to. Currently accepts the membership ID.</p>
    /// This field is required.
    pub fn membership_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the membership that the configured table association belongs to. Currently accepts the membership ID.</p>
    pub fn set_membership_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_identifier = input;
        self
    }
    /// <p>A unique identifier for the membership that the configured table association belongs to. Currently accepts the membership ID.</p>
    pub fn get_membership_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_identifier
    }
    /// <p>The identiﬁer for the conﬁgured table association that's related to the analysis rule.</p>
    /// This field is required.
    pub fn configured_table_association_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configured_table_association_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identiﬁer for the conﬁgured table association that's related to the analysis rule.</p>
    pub fn set_configured_table_association_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configured_table_association_identifier = input;
        self
    }
    /// <p>The identiﬁer for the conﬁgured table association that's related to the analysis rule.</p>
    pub fn get_configured_table_association_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.configured_table_association_identifier
    }
    /// <p>The type of analysis rule that you want to retrieve.</p>
    /// This field is required.
    pub fn analysis_rule_type(mut self, input: crate::types::ConfiguredTableAssociationAnalysisRuleType) -> Self {
        self.analysis_rule_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of analysis rule that you want to retrieve.</p>
    pub fn set_analysis_rule_type(mut self, input: ::std::option::Option<crate::types::ConfiguredTableAssociationAnalysisRuleType>) -> Self {
        self.analysis_rule_type = input;
        self
    }
    /// <p>The type of analysis rule that you want to retrieve.</p>
    pub fn get_analysis_rule_type(&self) -> &::std::option::Option<crate::types::ConfiguredTableAssociationAnalysisRuleType> {
        &self.analysis_rule_type
    }
    /// Consumes the builder and constructs a [`GetConfiguredTableAssociationAnalysisRuleInput`](crate::operation::get_configured_table_association_analysis_rule::GetConfiguredTableAssociationAnalysisRuleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_configured_table_association_analysis_rule::GetConfiguredTableAssociationAnalysisRuleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_configured_table_association_analysis_rule::GetConfiguredTableAssociationAnalysisRuleInput {
                membership_identifier: self.membership_identifier,
                configured_table_association_identifier: self.configured_table_association_identifier,
                analysis_rule_type: self.analysis_rule_type,
            },
        )
    }
}
