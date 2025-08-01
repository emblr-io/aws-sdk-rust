// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the configuration settings for a <code>Form</code> user interface (UI) element for an Amplify app. A form is a component you can add to your project by specifying a data source as the default configuration for the form.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Form {
    /// <p>The unique ID of the Amplify app associated with the form.</p>
    pub app_id: ::std::string::String,
    /// <p>The name of the backend environment that is a part of the Amplify app.</p>
    pub environment_name: ::std::string::String,
    /// <p>The unique ID of the form.</p>
    pub id: ::std::string::String,
    /// <p>The name of the form.</p>
    pub name: ::std::string::String,
    /// <p>The operation to perform on the specified form.</p>
    pub form_action_type: crate::types::FormActionType,
    /// <p>Stores the configuration for the form's style.</p>
    pub style: ::std::option::Option<crate::types::FormStyle>,
    /// <p>The type of data source to use to create the form.</p>
    pub data_type: ::std::option::Option<crate::types::FormDataTypeConfig>,
    /// <p>Stores the information about the form's fields.</p>
    pub fields: ::std::collections::HashMap<::std::string::String, crate::types::FieldConfig>,
    /// <p>Stores the visual helper elements for the form that are not associated with any data.</p>
    pub sectional_elements: ::std::collections::HashMap<::std::string::String, crate::types::SectionalElement>,
    /// <p>The schema version of the form when it was imported.</p>
    pub schema_version: ::std::string::String,
    /// <p>One or more key-value pairs to use when tagging the form.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Stores the call to action configuration for the form.</p>
    pub cta: ::std::option::Option<crate::types::FormCta>,
    /// <p>Specifies an icon or decoration to display on the form.</p>
    pub label_decorator: ::std::option::Option<crate::types::LabelDecorator>,
}
impl Form {
    /// <p>The unique ID of the Amplify app associated with the form.</p>
    pub fn app_id(&self) -> &str {
        use std::ops::Deref;
        self.app_id.deref()
    }
    /// <p>The name of the backend environment that is a part of the Amplify app.</p>
    pub fn environment_name(&self) -> &str {
        use std::ops::Deref;
        self.environment_name.deref()
    }
    /// <p>The unique ID of the form.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of the form.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The operation to perform on the specified form.</p>
    pub fn form_action_type(&self) -> &crate::types::FormActionType {
        &self.form_action_type
    }
    /// <p>Stores the configuration for the form's style.</p>
    pub fn style(&self) -> ::std::option::Option<&crate::types::FormStyle> {
        self.style.as_ref()
    }
    /// <p>The type of data source to use to create the form.</p>
    pub fn data_type(&self) -> ::std::option::Option<&crate::types::FormDataTypeConfig> {
        self.data_type.as_ref()
    }
    /// <p>Stores the information about the form's fields.</p>
    pub fn fields(&self) -> &::std::collections::HashMap<::std::string::String, crate::types::FieldConfig> {
        &self.fields
    }
    /// <p>Stores the visual helper elements for the form that are not associated with any data.</p>
    pub fn sectional_elements(&self) -> &::std::collections::HashMap<::std::string::String, crate::types::SectionalElement> {
        &self.sectional_elements
    }
    /// <p>The schema version of the form when it was imported.</p>
    pub fn schema_version(&self) -> &str {
        use std::ops::Deref;
        self.schema_version.deref()
    }
    /// <p>One or more key-value pairs to use when tagging the form.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Stores the call to action configuration for the form.</p>
    pub fn cta(&self) -> ::std::option::Option<&crate::types::FormCta> {
        self.cta.as_ref()
    }
    /// <p>Specifies an icon or decoration to display on the form.</p>
    pub fn label_decorator(&self) -> ::std::option::Option<&crate::types::LabelDecorator> {
        self.label_decorator.as_ref()
    }
}
impl Form {
    /// Creates a new builder-style object to manufacture [`Form`](crate::types::Form).
    pub fn builder() -> crate::types::builders::FormBuilder {
        crate::types::builders::FormBuilder::default()
    }
}

/// A builder for [`Form`](crate::types::Form).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FormBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) form_action_type: ::std::option::Option<crate::types::FormActionType>,
    pub(crate) style: ::std::option::Option<crate::types::FormStyle>,
    pub(crate) data_type: ::std::option::Option<crate::types::FormDataTypeConfig>,
    pub(crate) fields: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::FieldConfig>>,
    pub(crate) sectional_elements: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::SectionalElement>>,
    pub(crate) schema_version: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) cta: ::std::option::Option<crate::types::FormCta>,
    pub(crate) label_decorator: ::std::option::Option<crate::types::LabelDecorator>,
}
impl FormBuilder {
    /// <p>The unique ID of the Amplify app associated with the form.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the Amplify app associated with the form.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The unique ID of the Amplify app associated with the form.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The name of the backend environment that is a part of the Amplify app.</p>
    /// This field is required.
    pub fn environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the backend environment that is a part of the Amplify app.</p>
    pub fn set_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_name = input;
        self
    }
    /// <p>The name of the backend environment that is a part of the Amplify app.</p>
    pub fn get_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_name
    }
    /// <p>The unique ID of the form.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the form.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique ID of the form.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the form.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the form.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the form.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The operation to perform on the specified form.</p>
    /// This field is required.
    pub fn form_action_type(mut self, input: crate::types::FormActionType) -> Self {
        self.form_action_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to perform on the specified form.</p>
    pub fn set_form_action_type(mut self, input: ::std::option::Option<crate::types::FormActionType>) -> Self {
        self.form_action_type = input;
        self
    }
    /// <p>The operation to perform on the specified form.</p>
    pub fn get_form_action_type(&self) -> &::std::option::Option<crate::types::FormActionType> {
        &self.form_action_type
    }
    /// <p>Stores the configuration for the form's style.</p>
    /// This field is required.
    pub fn style(mut self, input: crate::types::FormStyle) -> Self {
        self.style = ::std::option::Option::Some(input);
        self
    }
    /// <p>Stores the configuration for the form's style.</p>
    pub fn set_style(mut self, input: ::std::option::Option<crate::types::FormStyle>) -> Self {
        self.style = input;
        self
    }
    /// <p>Stores the configuration for the form's style.</p>
    pub fn get_style(&self) -> &::std::option::Option<crate::types::FormStyle> {
        &self.style
    }
    /// <p>The type of data source to use to create the form.</p>
    /// This field is required.
    pub fn data_type(mut self, input: crate::types::FormDataTypeConfig) -> Self {
        self.data_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of data source to use to create the form.</p>
    pub fn set_data_type(mut self, input: ::std::option::Option<crate::types::FormDataTypeConfig>) -> Self {
        self.data_type = input;
        self
    }
    /// <p>The type of data source to use to create the form.</p>
    pub fn get_data_type(&self) -> &::std::option::Option<crate::types::FormDataTypeConfig> {
        &self.data_type
    }
    /// Adds a key-value pair to `fields`.
    ///
    /// To override the contents of this collection use [`set_fields`](Self::set_fields).
    ///
    /// <p>Stores the information about the form's fields.</p>
    pub fn fields(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::FieldConfig) -> Self {
        let mut hash_map = self.fields.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.fields = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Stores the information about the form's fields.</p>
    pub fn set_fields(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::FieldConfig>>) -> Self {
        self.fields = input;
        self
    }
    /// <p>Stores the information about the form's fields.</p>
    pub fn get_fields(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::FieldConfig>> {
        &self.fields
    }
    /// Adds a key-value pair to `sectional_elements`.
    ///
    /// To override the contents of this collection use [`set_sectional_elements`](Self::set_sectional_elements).
    ///
    /// <p>Stores the visual helper elements for the form that are not associated with any data.</p>
    pub fn sectional_elements(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::SectionalElement) -> Self {
        let mut hash_map = self.sectional_elements.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.sectional_elements = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Stores the visual helper elements for the form that are not associated with any data.</p>
    pub fn set_sectional_elements(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::SectionalElement>>,
    ) -> Self {
        self.sectional_elements = input;
        self
    }
    /// <p>Stores the visual helper elements for the form that are not associated with any data.</p>
    pub fn get_sectional_elements(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::SectionalElement>> {
        &self.sectional_elements
    }
    /// <p>The schema version of the form when it was imported.</p>
    /// This field is required.
    pub fn schema_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The schema version of the form when it was imported.</p>
    pub fn set_schema_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_version = input;
        self
    }
    /// <p>The schema version of the form when it was imported.</p>
    pub fn get_schema_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_version
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>One or more key-value pairs to use when tagging the form.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>One or more key-value pairs to use when tagging the form.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>One or more key-value pairs to use when tagging the form.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>Stores the call to action configuration for the form.</p>
    pub fn cta(mut self, input: crate::types::FormCta) -> Self {
        self.cta = ::std::option::Option::Some(input);
        self
    }
    /// <p>Stores the call to action configuration for the form.</p>
    pub fn set_cta(mut self, input: ::std::option::Option<crate::types::FormCta>) -> Self {
        self.cta = input;
        self
    }
    /// <p>Stores the call to action configuration for the form.</p>
    pub fn get_cta(&self) -> &::std::option::Option<crate::types::FormCta> {
        &self.cta
    }
    /// <p>Specifies an icon or decoration to display on the form.</p>
    pub fn label_decorator(mut self, input: crate::types::LabelDecorator) -> Self {
        self.label_decorator = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies an icon or decoration to display on the form.</p>
    pub fn set_label_decorator(mut self, input: ::std::option::Option<crate::types::LabelDecorator>) -> Self {
        self.label_decorator = input;
        self
    }
    /// <p>Specifies an icon or decoration to display on the form.</p>
    pub fn get_label_decorator(&self) -> &::std::option::Option<crate::types::LabelDecorator> {
        &self.label_decorator
    }
    /// Consumes the builder and constructs a [`Form`](crate::types::Form).
    /// This method will fail if any of the following fields are not set:
    /// - [`app_id`](crate::types::builders::FormBuilder::app_id)
    /// - [`environment_name`](crate::types::builders::FormBuilder::environment_name)
    /// - [`id`](crate::types::builders::FormBuilder::id)
    /// - [`name`](crate::types::builders::FormBuilder::name)
    /// - [`form_action_type`](crate::types::builders::FormBuilder::form_action_type)
    /// - [`fields`](crate::types::builders::FormBuilder::fields)
    /// - [`sectional_elements`](crate::types::builders::FormBuilder::sectional_elements)
    /// - [`schema_version`](crate::types::builders::FormBuilder::schema_version)
    pub fn build(self) -> ::std::result::Result<crate::types::Form, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Form {
            app_id: self.app_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_id",
                    "app_id was not specified but it is required when building Form",
                )
            })?,
            environment_name: self.environment_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "environment_name",
                    "environment_name was not specified but it is required when building Form",
                )
            })?,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field("id", "id was not specified but it is required when building Form")
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building Form",
                )
            })?,
            form_action_type: self.form_action_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "form_action_type",
                    "form_action_type was not specified but it is required when building Form",
                )
            })?,
            style: self.style,
            data_type: self.data_type,
            fields: self.fields.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "fields",
                    "fields was not specified but it is required when building Form",
                )
            })?,
            sectional_elements: self.sectional_elements.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sectional_elements",
                    "sectional_elements was not specified but it is required when building Form",
                )
            })?,
            schema_version: self.schema_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "schema_version",
                    "schema_version was not specified but it is required when building Form",
                )
            })?,
            tags: self.tags,
            cta: self.cta,
            label_decorator: self.label_decorator,
        })
    }
}
