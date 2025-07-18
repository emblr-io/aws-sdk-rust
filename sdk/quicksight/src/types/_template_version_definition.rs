// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The detailed definition of a template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TemplateVersionDefinition {
    /// <p>An array of dataset configurations. These configurations define the required columns for each dataset used within a template.</p>
    pub data_set_configurations: ::std::vec::Vec<crate::types::DataSetConfiguration>,
    /// <p>An array of sheet definitions for a template.</p>
    pub sheets: ::std::option::Option<::std::vec::Vec<crate::types::SheetDefinition>>,
    /// <p>An array of calculated field definitions for the template.</p>
    pub calculated_fields: ::std::option::Option<::std::vec::Vec<crate::types::CalculatedField>>,
    /// <p>An array of parameter declarations for a template.</p>
    /// <p><i>Parameters</i> are named variables that can transfer a value for use by an action or an object.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/parameters-in-quicksight.html">Parameters in Amazon QuickSight</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub parameter_declarations: ::std::option::Option<::std::vec::Vec<crate::types::ParameterDeclaration>>,
    /// <p>Filter definitions for a template.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/filtering-visual-data.html">Filtering Data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub filter_groups: ::std::option::Option<::std::vec::Vec<crate::types::FilterGroup>>,
    /// <p>An array of template-level column configurations. Column configurations are used to set default formatting for a column that's used throughout a template.</p>
    pub column_configurations: ::std::option::Option<::std::vec::Vec<crate::types::ColumnConfiguration>>,
    /// <p>The configuration for default analysis settings.</p>
    pub analysis_defaults: ::std::option::Option<crate::types::AnalysisDefaults>,
    /// <p>An array of option definitions for a template.</p>
    pub options: ::std::option::Option<crate::types::AssetOptions>,
    /// <p>A structure that describes the query execution options.</p>
    pub query_execution_options: ::std::option::Option<crate::types::QueryExecutionOptions>,
    /// <p>The static files for the definition.</p>
    pub static_files: ::std::option::Option<::std::vec::Vec<crate::types::StaticFile>>,
}
impl TemplateVersionDefinition {
    /// <p>An array of dataset configurations. These configurations define the required columns for each dataset used within a template.</p>
    pub fn data_set_configurations(&self) -> &[crate::types::DataSetConfiguration] {
        use std::ops::Deref;
        self.data_set_configurations.deref()
    }
    /// <p>An array of sheet definitions for a template.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sheets.is_none()`.
    pub fn sheets(&self) -> &[crate::types::SheetDefinition] {
        self.sheets.as_deref().unwrap_or_default()
    }
    /// <p>An array of calculated field definitions for the template.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.calculated_fields.is_none()`.
    pub fn calculated_fields(&self) -> &[crate::types::CalculatedField] {
        self.calculated_fields.as_deref().unwrap_or_default()
    }
    /// <p>An array of parameter declarations for a template.</p>
    /// <p><i>Parameters</i> are named variables that can transfer a value for use by an action or an object.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/parameters-in-quicksight.html">Parameters in Amazon QuickSight</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameter_declarations.is_none()`.
    pub fn parameter_declarations(&self) -> &[crate::types::ParameterDeclaration] {
        self.parameter_declarations.as_deref().unwrap_or_default()
    }
    /// <p>Filter definitions for a template.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/filtering-visual-data.html">Filtering Data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filter_groups.is_none()`.
    pub fn filter_groups(&self) -> &[crate::types::FilterGroup] {
        self.filter_groups.as_deref().unwrap_or_default()
    }
    /// <p>An array of template-level column configurations. Column configurations are used to set default formatting for a column that's used throughout a template.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.column_configurations.is_none()`.
    pub fn column_configurations(&self) -> &[crate::types::ColumnConfiguration] {
        self.column_configurations.as_deref().unwrap_or_default()
    }
    /// <p>The configuration for default analysis settings.</p>
    pub fn analysis_defaults(&self) -> ::std::option::Option<&crate::types::AnalysisDefaults> {
        self.analysis_defaults.as_ref()
    }
    /// <p>An array of option definitions for a template.</p>
    pub fn options(&self) -> ::std::option::Option<&crate::types::AssetOptions> {
        self.options.as_ref()
    }
    /// <p>A structure that describes the query execution options.</p>
    pub fn query_execution_options(&self) -> ::std::option::Option<&crate::types::QueryExecutionOptions> {
        self.query_execution_options.as_ref()
    }
    /// <p>The static files for the definition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.static_files.is_none()`.
    pub fn static_files(&self) -> &[crate::types::StaticFile] {
        self.static_files.as_deref().unwrap_or_default()
    }
}
impl TemplateVersionDefinition {
    /// Creates a new builder-style object to manufacture [`TemplateVersionDefinition`](crate::types::TemplateVersionDefinition).
    pub fn builder() -> crate::types::builders::TemplateVersionDefinitionBuilder {
        crate::types::builders::TemplateVersionDefinitionBuilder::default()
    }
}

/// A builder for [`TemplateVersionDefinition`](crate::types::TemplateVersionDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TemplateVersionDefinitionBuilder {
    pub(crate) data_set_configurations: ::std::option::Option<::std::vec::Vec<crate::types::DataSetConfiguration>>,
    pub(crate) sheets: ::std::option::Option<::std::vec::Vec<crate::types::SheetDefinition>>,
    pub(crate) calculated_fields: ::std::option::Option<::std::vec::Vec<crate::types::CalculatedField>>,
    pub(crate) parameter_declarations: ::std::option::Option<::std::vec::Vec<crate::types::ParameterDeclaration>>,
    pub(crate) filter_groups: ::std::option::Option<::std::vec::Vec<crate::types::FilterGroup>>,
    pub(crate) column_configurations: ::std::option::Option<::std::vec::Vec<crate::types::ColumnConfiguration>>,
    pub(crate) analysis_defaults: ::std::option::Option<crate::types::AnalysisDefaults>,
    pub(crate) options: ::std::option::Option<crate::types::AssetOptions>,
    pub(crate) query_execution_options: ::std::option::Option<crate::types::QueryExecutionOptions>,
    pub(crate) static_files: ::std::option::Option<::std::vec::Vec<crate::types::StaticFile>>,
}
impl TemplateVersionDefinitionBuilder {
    /// Appends an item to `data_set_configurations`.
    ///
    /// To override the contents of this collection use [`set_data_set_configurations`](Self::set_data_set_configurations).
    ///
    /// <p>An array of dataset configurations. These configurations define the required columns for each dataset used within a template.</p>
    pub fn data_set_configurations(mut self, input: crate::types::DataSetConfiguration) -> Self {
        let mut v = self.data_set_configurations.unwrap_or_default();
        v.push(input);
        self.data_set_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of dataset configurations. These configurations define the required columns for each dataset used within a template.</p>
    pub fn set_data_set_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataSetConfiguration>>) -> Self {
        self.data_set_configurations = input;
        self
    }
    /// <p>An array of dataset configurations. These configurations define the required columns for each dataset used within a template.</p>
    pub fn get_data_set_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataSetConfiguration>> {
        &self.data_set_configurations
    }
    /// Appends an item to `sheets`.
    ///
    /// To override the contents of this collection use [`set_sheets`](Self::set_sheets).
    ///
    /// <p>An array of sheet definitions for a template.</p>
    pub fn sheets(mut self, input: crate::types::SheetDefinition) -> Self {
        let mut v = self.sheets.unwrap_or_default();
        v.push(input);
        self.sheets = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of sheet definitions for a template.</p>
    pub fn set_sheets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SheetDefinition>>) -> Self {
        self.sheets = input;
        self
    }
    /// <p>An array of sheet definitions for a template.</p>
    pub fn get_sheets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SheetDefinition>> {
        &self.sheets
    }
    /// Appends an item to `calculated_fields`.
    ///
    /// To override the contents of this collection use [`set_calculated_fields`](Self::set_calculated_fields).
    ///
    /// <p>An array of calculated field definitions for the template.</p>
    pub fn calculated_fields(mut self, input: crate::types::CalculatedField) -> Self {
        let mut v = self.calculated_fields.unwrap_or_default();
        v.push(input);
        self.calculated_fields = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of calculated field definitions for the template.</p>
    pub fn set_calculated_fields(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CalculatedField>>) -> Self {
        self.calculated_fields = input;
        self
    }
    /// <p>An array of calculated field definitions for the template.</p>
    pub fn get_calculated_fields(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CalculatedField>> {
        &self.calculated_fields
    }
    /// Appends an item to `parameter_declarations`.
    ///
    /// To override the contents of this collection use [`set_parameter_declarations`](Self::set_parameter_declarations).
    ///
    /// <p>An array of parameter declarations for a template.</p>
    /// <p><i>Parameters</i> are named variables that can transfer a value for use by an action or an object.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/parameters-in-quicksight.html">Parameters in Amazon QuickSight</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn parameter_declarations(mut self, input: crate::types::ParameterDeclaration) -> Self {
        let mut v = self.parameter_declarations.unwrap_or_default();
        v.push(input);
        self.parameter_declarations = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of parameter declarations for a template.</p>
    /// <p><i>Parameters</i> are named variables that can transfer a value for use by an action or an object.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/parameters-in-quicksight.html">Parameters in Amazon QuickSight</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn set_parameter_declarations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ParameterDeclaration>>) -> Self {
        self.parameter_declarations = input;
        self
    }
    /// <p>An array of parameter declarations for a template.</p>
    /// <p><i>Parameters</i> are named variables that can transfer a value for use by an action or an object.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/parameters-in-quicksight.html">Parameters in Amazon QuickSight</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn get_parameter_declarations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ParameterDeclaration>> {
        &self.parameter_declarations
    }
    /// Appends an item to `filter_groups`.
    ///
    /// To override the contents of this collection use [`set_filter_groups`](Self::set_filter_groups).
    ///
    /// <p>Filter definitions for a template.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/filtering-visual-data.html">Filtering Data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn filter_groups(mut self, input: crate::types::FilterGroup) -> Self {
        let mut v = self.filter_groups.unwrap_or_default();
        v.push(input);
        self.filter_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filter definitions for a template.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/filtering-visual-data.html">Filtering Data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn set_filter_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FilterGroup>>) -> Self {
        self.filter_groups = input;
        self
    }
    /// <p>Filter definitions for a template.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/filtering-visual-data.html">Filtering Data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn get_filter_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilterGroup>> {
        &self.filter_groups
    }
    /// Appends an item to `column_configurations`.
    ///
    /// To override the contents of this collection use [`set_column_configurations`](Self::set_column_configurations).
    ///
    /// <p>An array of template-level column configurations. Column configurations are used to set default formatting for a column that's used throughout a template.</p>
    pub fn column_configurations(mut self, input: crate::types::ColumnConfiguration) -> Self {
        let mut v = self.column_configurations.unwrap_or_default();
        v.push(input);
        self.column_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of template-level column configurations. Column configurations are used to set default formatting for a column that's used throughout a template.</p>
    pub fn set_column_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ColumnConfiguration>>) -> Self {
        self.column_configurations = input;
        self
    }
    /// <p>An array of template-level column configurations. Column configurations are used to set default formatting for a column that's used throughout a template.</p>
    pub fn get_column_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ColumnConfiguration>> {
        &self.column_configurations
    }
    /// <p>The configuration for default analysis settings.</p>
    pub fn analysis_defaults(mut self, input: crate::types::AnalysisDefaults) -> Self {
        self.analysis_defaults = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for default analysis settings.</p>
    pub fn set_analysis_defaults(mut self, input: ::std::option::Option<crate::types::AnalysisDefaults>) -> Self {
        self.analysis_defaults = input;
        self
    }
    /// <p>The configuration for default analysis settings.</p>
    pub fn get_analysis_defaults(&self) -> &::std::option::Option<crate::types::AnalysisDefaults> {
        &self.analysis_defaults
    }
    /// <p>An array of option definitions for a template.</p>
    pub fn options(mut self, input: crate::types::AssetOptions) -> Self {
        self.options = ::std::option::Option::Some(input);
        self
    }
    /// <p>An array of option definitions for a template.</p>
    pub fn set_options(mut self, input: ::std::option::Option<crate::types::AssetOptions>) -> Self {
        self.options = input;
        self
    }
    /// <p>An array of option definitions for a template.</p>
    pub fn get_options(&self) -> &::std::option::Option<crate::types::AssetOptions> {
        &self.options
    }
    /// <p>A structure that describes the query execution options.</p>
    pub fn query_execution_options(mut self, input: crate::types::QueryExecutionOptions) -> Self {
        self.query_execution_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that describes the query execution options.</p>
    pub fn set_query_execution_options(mut self, input: ::std::option::Option<crate::types::QueryExecutionOptions>) -> Self {
        self.query_execution_options = input;
        self
    }
    /// <p>A structure that describes the query execution options.</p>
    pub fn get_query_execution_options(&self) -> &::std::option::Option<crate::types::QueryExecutionOptions> {
        &self.query_execution_options
    }
    /// Appends an item to `static_files`.
    ///
    /// To override the contents of this collection use [`set_static_files`](Self::set_static_files).
    ///
    /// <p>The static files for the definition.</p>
    pub fn static_files(mut self, input: crate::types::StaticFile) -> Self {
        let mut v = self.static_files.unwrap_or_default();
        v.push(input);
        self.static_files = ::std::option::Option::Some(v);
        self
    }
    /// <p>The static files for the definition.</p>
    pub fn set_static_files(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StaticFile>>) -> Self {
        self.static_files = input;
        self
    }
    /// <p>The static files for the definition.</p>
    pub fn get_static_files(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StaticFile>> {
        &self.static_files
    }
    /// Consumes the builder and constructs a [`TemplateVersionDefinition`](crate::types::TemplateVersionDefinition).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_set_configurations`](crate::types::builders::TemplateVersionDefinitionBuilder::data_set_configurations)
    pub fn build(self) -> ::std::result::Result<crate::types::TemplateVersionDefinition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TemplateVersionDefinition {
            data_set_configurations: self.data_set_configurations.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_set_configurations",
                    "data_set_configurations was not specified but it is required when building TemplateVersionDefinition",
                )
            })?,
            sheets: self.sheets,
            calculated_fields: self.calculated_fields,
            parameter_declarations: self.parameter_declarations,
            filter_groups: self.filter_groups,
            column_configurations: self.column_configurations,
            analysis_defaults: self.analysis_defaults,
            options: self.options,
            query_execution_options: self.query_execution_options,
            static_files: self.static_files,
        })
    }
}
