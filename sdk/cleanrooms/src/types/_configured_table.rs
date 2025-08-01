// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A table that has been configured for use in a collaboration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfiguredTable {
    /// <p>The unique ID for the configured table.</p>
    pub id: ::std::string::String,
    /// <p>The unique ARN for the configured table.</p>
    pub arn: ::std::string::String,
    /// <p>A name for the configured table.</p>
    pub name: ::std::string::String,
    /// <p>A description for the configured table.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The table that this configured table represents.</p>
    pub table_reference: ::std::option::Option<crate::types::TableReference>,
    /// <p>The time the configured table was created.</p>
    pub create_time: ::aws_smithy_types::DateTime,
    /// <p>The time the configured table was last updated</p>
    pub update_time: ::aws_smithy_types::DateTime,
    /// <p>The types of analysis rules associated with this configured table. Currently, only one analysis rule may be associated with a configured table.</p>
    pub analysis_rule_types: ::std::vec::Vec<crate::types::ConfiguredTableAnalysisRuleType>,
    /// <p>The analysis method for the configured table.</p>
    /// <p><code>DIRECT_QUERY</code> allows SQL queries to be run directly on this table.</p>
    /// <p><code>DIRECT_JOB</code> allows PySpark jobs to be run directly on this table.</p>
    /// <p><code>MULTIPLE</code> allows both SQL queries and PySpark jobs to be run directly on this table.</p>
    pub analysis_method: crate::types::AnalysisMethod,
    /// <p>The columns within the underlying Glue table that can be utilized within collaborations.</p>
    pub allowed_columns: ::std::vec::Vec<::std::string::String>,
    /// <p>The selected analysis methods for the configured table.</p>
    pub selected_analysis_methods: ::std::option::Option<::std::vec::Vec<crate::types::SelectedAnalysisMethod>>,
}
impl ConfiguredTable {
    /// <p>The unique ID for the configured table.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The unique ARN for the configured table.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>A name for the configured table.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>A description for the configured table.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The table that this configured table represents.</p>
    pub fn table_reference(&self) -> ::std::option::Option<&crate::types::TableReference> {
        self.table_reference.as_ref()
    }
    /// <p>The time the configured table was created.</p>
    pub fn create_time(&self) -> &::aws_smithy_types::DateTime {
        &self.create_time
    }
    /// <p>The time the configured table was last updated</p>
    pub fn update_time(&self) -> &::aws_smithy_types::DateTime {
        &self.update_time
    }
    /// <p>The types of analysis rules associated with this configured table. Currently, only one analysis rule may be associated with a configured table.</p>
    pub fn analysis_rule_types(&self) -> &[crate::types::ConfiguredTableAnalysisRuleType] {
        use std::ops::Deref;
        self.analysis_rule_types.deref()
    }
    /// <p>The analysis method for the configured table.</p>
    /// <p><code>DIRECT_QUERY</code> allows SQL queries to be run directly on this table.</p>
    /// <p><code>DIRECT_JOB</code> allows PySpark jobs to be run directly on this table.</p>
    /// <p><code>MULTIPLE</code> allows both SQL queries and PySpark jobs to be run directly on this table.</p>
    pub fn analysis_method(&self) -> &crate::types::AnalysisMethod {
        &self.analysis_method
    }
    /// <p>The columns within the underlying Glue table that can be utilized within collaborations.</p>
    pub fn allowed_columns(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.allowed_columns.deref()
    }
    /// <p>The selected analysis methods for the configured table.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.selected_analysis_methods.is_none()`.
    pub fn selected_analysis_methods(&self) -> &[crate::types::SelectedAnalysisMethod] {
        self.selected_analysis_methods.as_deref().unwrap_or_default()
    }
}
impl ConfiguredTable {
    /// Creates a new builder-style object to manufacture [`ConfiguredTable`](crate::types::ConfiguredTable).
    pub fn builder() -> crate::types::builders::ConfiguredTableBuilder {
        crate::types::builders::ConfiguredTableBuilder::default()
    }
}

/// A builder for [`ConfiguredTable`](crate::types::ConfiguredTable).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfiguredTableBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) table_reference: ::std::option::Option<crate::types::TableReference>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) analysis_rule_types: ::std::option::Option<::std::vec::Vec<crate::types::ConfiguredTableAnalysisRuleType>>,
    pub(crate) analysis_method: ::std::option::Option<crate::types::AnalysisMethod>,
    pub(crate) allowed_columns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) selected_analysis_methods: ::std::option::Option<::std::vec::Vec<crate::types::SelectedAnalysisMethod>>,
}
impl ConfiguredTableBuilder {
    /// <p>The unique ID for the configured table.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID for the configured table.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique ID for the configured table.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The unique ARN for the configured table.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ARN for the configured table.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The unique ARN for the configured table.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>A name for the configured table.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the configured table.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for the configured table.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description for the configured table.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the configured table.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the configured table.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The table that this configured table represents.</p>
    /// This field is required.
    pub fn table_reference(mut self, input: crate::types::TableReference) -> Self {
        self.table_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The table that this configured table represents.</p>
    pub fn set_table_reference(mut self, input: ::std::option::Option<crate::types::TableReference>) -> Self {
        self.table_reference = input;
        self
    }
    /// <p>The table that this configured table represents.</p>
    pub fn get_table_reference(&self) -> &::std::option::Option<crate::types::TableReference> {
        &self.table_reference
    }
    /// <p>The time the configured table was created.</p>
    /// This field is required.
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the configured table was created.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time the configured table was created.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The time the configured table was last updated</p>
    /// This field is required.
    pub fn update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the configured table was last updated</p>
    pub fn set_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_time = input;
        self
    }
    /// <p>The time the configured table was last updated</p>
    pub fn get_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_time
    }
    /// Appends an item to `analysis_rule_types`.
    ///
    /// To override the contents of this collection use [`set_analysis_rule_types`](Self::set_analysis_rule_types).
    ///
    /// <p>The types of analysis rules associated with this configured table. Currently, only one analysis rule may be associated with a configured table.</p>
    pub fn analysis_rule_types(mut self, input: crate::types::ConfiguredTableAnalysisRuleType) -> Self {
        let mut v = self.analysis_rule_types.unwrap_or_default();
        v.push(input);
        self.analysis_rule_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The types of analysis rules associated with this configured table. Currently, only one analysis rule may be associated with a configured table.</p>
    pub fn set_analysis_rule_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConfiguredTableAnalysisRuleType>>) -> Self {
        self.analysis_rule_types = input;
        self
    }
    /// <p>The types of analysis rules associated with this configured table. Currently, only one analysis rule may be associated with a configured table.</p>
    pub fn get_analysis_rule_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConfiguredTableAnalysisRuleType>> {
        &self.analysis_rule_types
    }
    /// <p>The analysis method for the configured table.</p>
    /// <p><code>DIRECT_QUERY</code> allows SQL queries to be run directly on this table.</p>
    /// <p><code>DIRECT_JOB</code> allows PySpark jobs to be run directly on this table.</p>
    /// <p><code>MULTIPLE</code> allows both SQL queries and PySpark jobs to be run directly on this table.</p>
    /// This field is required.
    pub fn analysis_method(mut self, input: crate::types::AnalysisMethod) -> Self {
        self.analysis_method = ::std::option::Option::Some(input);
        self
    }
    /// <p>The analysis method for the configured table.</p>
    /// <p><code>DIRECT_QUERY</code> allows SQL queries to be run directly on this table.</p>
    /// <p><code>DIRECT_JOB</code> allows PySpark jobs to be run directly on this table.</p>
    /// <p><code>MULTIPLE</code> allows both SQL queries and PySpark jobs to be run directly on this table.</p>
    pub fn set_analysis_method(mut self, input: ::std::option::Option<crate::types::AnalysisMethod>) -> Self {
        self.analysis_method = input;
        self
    }
    /// <p>The analysis method for the configured table.</p>
    /// <p><code>DIRECT_QUERY</code> allows SQL queries to be run directly on this table.</p>
    /// <p><code>DIRECT_JOB</code> allows PySpark jobs to be run directly on this table.</p>
    /// <p><code>MULTIPLE</code> allows both SQL queries and PySpark jobs to be run directly on this table.</p>
    pub fn get_analysis_method(&self) -> &::std::option::Option<crate::types::AnalysisMethod> {
        &self.analysis_method
    }
    /// Appends an item to `allowed_columns`.
    ///
    /// To override the contents of this collection use [`set_allowed_columns`](Self::set_allowed_columns).
    ///
    /// <p>The columns within the underlying Glue table that can be utilized within collaborations.</p>
    pub fn allowed_columns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.allowed_columns.unwrap_or_default();
        v.push(input.into());
        self.allowed_columns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The columns within the underlying Glue table that can be utilized within collaborations.</p>
    pub fn set_allowed_columns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.allowed_columns = input;
        self
    }
    /// <p>The columns within the underlying Glue table that can be utilized within collaborations.</p>
    pub fn get_allowed_columns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.allowed_columns
    }
    /// Appends an item to `selected_analysis_methods`.
    ///
    /// To override the contents of this collection use [`set_selected_analysis_methods`](Self::set_selected_analysis_methods).
    ///
    /// <p>The selected analysis methods for the configured table.</p>
    pub fn selected_analysis_methods(mut self, input: crate::types::SelectedAnalysisMethod) -> Self {
        let mut v = self.selected_analysis_methods.unwrap_or_default();
        v.push(input);
        self.selected_analysis_methods = ::std::option::Option::Some(v);
        self
    }
    /// <p>The selected analysis methods for the configured table.</p>
    pub fn set_selected_analysis_methods(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SelectedAnalysisMethod>>) -> Self {
        self.selected_analysis_methods = input;
        self
    }
    /// <p>The selected analysis methods for the configured table.</p>
    pub fn get_selected_analysis_methods(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SelectedAnalysisMethod>> {
        &self.selected_analysis_methods
    }
    /// Consumes the builder and constructs a [`ConfiguredTable`](crate::types::ConfiguredTable).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::ConfiguredTableBuilder::id)
    /// - [`arn`](crate::types::builders::ConfiguredTableBuilder::arn)
    /// - [`name`](crate::types::builders::ConfiguredTableBuilder::name)
    /// - [`create_time`](crate::types::builders::ConfiguredTableBuilder::create_time)
    /// - [`update_time`](crate::types::builders::ConfiguredTableBuilder::update_time)
    /// - [`analysis_rule_types`](crate::types::builders::ConfiguredTableBuilder::analysis_rule_types)
    /// - [`analysis_method`](crate::types::builders::ConfiguredTableBuilder::analysis_method)
    /// - [`allowed_columns`](crate::types::builders::ConfiguredTableBuilder::allowed_columns)
    pub fn build(self) -> ::std::result::Result<crate::types::ConfiguredTable, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConfiguredTable {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building ConfiguredTable",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building ConfiguredTable",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ConfiguredTable",
                )
            })?,
            description: self.description,
            table_reference: self.table_reference,
            create_time: self.create_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "create_time",
                    "create_time was not specified but it is required when building ConfiguredTable",
                )
            })?,
            update_time: self.update_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "update_time",
                    "update_time was not specified but it is required when building ConfiguredTable",
                )
            })?,
            analysis_rule_types: self.analysis_rule_types.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "analysis_rule_types",
                    "analysis_rule_types was not specified but it is required when building ConfiguredTable",
                )
            })?,
            analysis_method: self.analysis_method.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "analysis_method",
                    "analysis_method was not specified but it is required when building ConfiguredTable",
                )
            })?,
            allowed_columns: self.allowed_columns.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "allowed_columns",
                    "allowed_columns was not specified but it is required when building ConfiguredTable",
                )
            })?,
            selected_analysis_methods: self.selected_analysis_methods,
        })
    }
}
