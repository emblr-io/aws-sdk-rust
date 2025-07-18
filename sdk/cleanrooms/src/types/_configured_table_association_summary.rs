// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configured table association summary for the objects listed by the request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfiguredTableAssociationSummary {
    /// <p>The unique configured table ID that this configured table association refers to.</p>
    pub configured_table_id: ::std::string::String,
    /// <p>The unique ID for the membership that the configured table association belongs to.</p>
    pub membership_id: ::std::string::String,
    /// <p>The unique ARN for the membership that the configured table association belongs to.</p>
    pub membership_arn: ::std::string::String,
    /// <p>The name of the configured table association. The table is identified by this name when running Protected Queries against the underlying data.</p>
    pub name: ::std::string::String,
    /// <p>The time the configured table association was created.</p>
    pub create_time: ::aws_smithy_types::DateTime,
    /// <p>The time the configured table association was last updated.</p>
    pub update_time: ::aws_smithy_types::DateTime,
    /// <p>The unique ID for the configured table association.</p>
    pub id: ::std::string::String,
    /// <p>The unique ARN for the configured table association.</p>
    pub arn: ::std::string::String,
    /// <p>The analysis rule types that are associated with the configured table associations in this summary.</p>
    pub analysis_rule_types: ::std::option::Option<::std::vec::Vec<crate::types::ConfiguredTableAssociationAnalysisRuleType>>,
}
impl ConfiguredTableAssociationSummary {
    /// <p>The unique configured table ID that this configured table association refers to.</p>
    pub fn configured_table_id(&self) -> &str {
        use std::ops::Deref;
        self.configured_table_id.deref()
    }
    /// <p>The unique ID for the membership that the configured table association belongs to.</p>
    pub fn membership_id(&self) -> &str {
        use std::ops::Deref;
        self.membership_id.deref()
    }
    /// <p>The unique ARN for the membership that the configured table association belongs to.</p>
    pub fn membership_arn(&self) -> &str {
        use std::ops::Deref;
        self.membership_arn.deref()
    }
    /// <p>The name of the configured table association. The table is identified by this name when running Protected Queries against the underlying data.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The time the configured table association was created.</p>
    pub fn create_time(&self) -> &::aws_smithy_types::DateTime {
        &self.create_time
    }
    /// <p>The time the configured table association was last updated.</p>
    pub fn update_time(&self) -> &::aws_smithy_types::DateTime {
        &self.update_time
    }
    /// <p>The unique ID for the configured table association.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The unique ARN for the configured table association.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The analysis rule types that are associated with the configured table associations in this summary.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.analysis_rule_types.is_none()`.
    pub fn analysis_rule_types(&self) -> &[crate::types::ConfiguredTableAssociationAnalysisRuleType] {
        self.analysis_rule_types.as_deref().unwrap_or_default()
    }
}
impl ConfiguredTableAssociationSummary {
    /// Creates a new builder-style object to manufacture [`ConfiguredTableAssociationSummary`](crate::types::ConfiguredTableAssociationSummary).
    pub fn builder() -> crate::types::builders::ConfiguredTableAssociationSummaryBuilder {
        crate::types::builders::ConfiguredTableAssociationSummaryBuilder::default()
    }
}

/// A builder for [`ConfiguredTableAssociationSummary`](crate::types::ConfiguredTableAssociationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfiguredTableAssociationSummaryBuilder {
    pub(crate) configured_table_id: ::std::option::Option<::std::string::String>,
    pub(crate) membership_id: ::std::option::Option<::std::string::String>,
    pub(crate) membership_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) analysis_rule_types: ::std::option::Option<::std::vec::Vec<crate::types::ConfiguredTableAssociationAnalysisRuleType>>,
}
impl ConfiguredTableAssociationSummaryBuilder {
    /// <p>The unique configured table ID that this configured table association refers to.</p>
    /// This field is required.
    pub fn configured_table_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configured_table_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique configured table ID that this configured table association refers to.</p>
    pub fn set_configured_table_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configured_table_id = input;
        self
    }
    /// <p>The unique configured table ID that this configured table association refers to.</p>
    pub fn get_configured_table_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.configured_table_id
    }
    /// <p>The unique ID for the membership that the configured table association belongs to.</p>
    /// This field is required.
    pub fn membership_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for the membership that the configured table association belongs to.</p>
    pub fn set_membership_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_id = input;
        self
    }
    /// <p>The unique ID for the membership that the configured table association belongs to.</p>
    pub fn get_membership_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_id
    }
    /// <p>The unique ARN for the membership that the configured table association belongs to.</p>
    /// This field is required.
    pub fn membership_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ARN for the membership that the configured table association belongs to.</p>
    pub fn set_membership_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_arn = input;
        self
    }
    /// <p>The unique ARN for the membership that the configured table association belongs to.</p>
    pub fn get_membership_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_arn
    }
    /// <p>The name of the configured table association. The table is identified by this name when running Protected Queries against the underlying data.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configured table association. The table is identified by this name when running Protected Queries against the underlying data.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the configured table association. The table is identified by this name when running Protected Queries against the underlying data.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The time the configured table association was created.</p>
    /// This field is required.
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the configured table association was created.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time the configured table association was created.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The time the configured table association was last updated.</p>
    /// This field is required.
    pub fn update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the configured table association was last updated.</p>
    pub fn set_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_time = input;
        self
    }
    /// <p>The time the configured table association was last updated.</p>
    pub fn get_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_time
    }
    /// <p>The unique ID for the configured table association.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for the configured table association.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique ID for the configured table association.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The unique ARN for the configured table association.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ARN for the configured table association.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The unique ARN for the configured table association.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Appends an item to `analysis_rule_types`.
    ///
    /// To override the contents of this collection use [`set_analysis_rule_types`](Self::set_analysis_rule_types).
    ///
    /// <p>The analysis rule types that are associated with the configured table associations in this summary.</p>
    pub fn analysis_rule_types(mut self, input: crate::types::ConfiguredTableAssociationAnalysisRuleType) -> Self {
        let mut v = self.analysis_rule_types.unwrap_or_default();
        v.push(input);
        self.analysis_rule_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The analysis rule types that are associated with the configured table associations in this summary.</p>
    pub fn set_analysis_rule_types(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ConfiguredTableAssociationAnalysisRuleType>>,
    ) -> Self {
        self.analysis_rule_types = input;
        self
    }
    /// <p>The analysis rule types that are associated with the configured table associations in this summary.</p>
    pub fn get_analysis_rule_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConfiguredTableAssociationAnalysisRuleType>> {
        &self.analysis_rule_types
    }
    /// Consumes the builder and constructs a [`ConfiguredTableAssociationSummary`](crate::types::ConfiguredTableAssociationSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`configured_table_id`](crate::types::builders::ConfiguredTableAssociationSummaryBuilder::configured_table_id)
    /// - [`membership_id`](crate::types::builders::ConfiguredTableAssociationSummaryBuilder::membership_id)
    /// - [`membership_arn`](crate::types::builders::ConfiguredTableAssociationSummaryBuilder::membership_arn)
    /// - [`name`](crate::types::builders::ConfiguredTableAssociationSummaryBuilder::name)
    /// - [`create_time`](crate::types::builders::ConfiguredTableAssociationSummaryBuilder::create_time)
    /// - [`update_time`](crate::types::builders::ConfiguredTableAssociationSummaryBuilder::update_time)
    /// - [`id`](crate::types::builders::ConfiguredTableAssociationSummaryBuilder::id)
    /// - [`arn`](crate::types::builders::ConfiguredTableAssociationSummaryBuilder::arn)
    pub fn build(self) -> ::std::result::Result<crate::types::ConfiguredTableAssociationSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConfiguredTableAssociationSummary {
            configured_table_id: self.configured_table_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "configured_table_id",
                    "configured_table_id was not specified but it is required when building ConfiguredTableAssociationSummary",
                )
            })?,
            membership_id: self.membership_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "membership_id",
                    "membership_id was not specified but it is required when building ConfiguredTableAssociationSummary",
                )
            })?,
            membership_arn: self.membership_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "membership_arn",
                    "membership_arn was not specified but it is required when building ConfiguredTableAssociationSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ConfiguredTableAssociationSummary",
                )
            })?,
            create_time: self.create_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "create_time",
                    "create_time was not specified but it is required when building ConfiguredTableAssociationSummary",
                )
            })?,
            update_time: self.update_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "update_time",
                    "update_time was not specified but it is required when building ConfiguredTableAssociationSummary",
                )
            })?,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building ConfiguredTableAssociationSummary",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building ConfiguredTableAssociationSummary",
                )
            })?,
            analysis_rule_types: self.analysis_rule_types,
        })
    }
}
