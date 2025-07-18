// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a composite model in an asset model. This object contains the asset property definitions that you define in the composite model.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssetModelCompositeModel {
    /// <p>The name of the composite model.</p>
    pub name: ::std::string::String,
    /// <p>The description of the composite model.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The type of the composite model. For alarm composite models, this type is <code>AWS/ALARM</code>.</p>
    pub r#type: ::std::string::String,
    /// <p>The asset property definitions for this composite model.</p>
    pub properties: ::std::option::Option<::std::vec::Vec<crate::types::AssetModelProperty>>,
    /// <p>The ID of the asset model composite model.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The external ID of the asset model composite model. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-ids">Using external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub external_id: ::std::option::Option<::std::string::String>,
}
impl AssetModelCompositeModel {
    /// <p>The name of the composite model.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description of the composite model.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The type of the composite model. For alarm composite models, this type is <code>AWS/ALARM</code>.</p>
    pub fn r#type(&self) -> &str {
        use std::ops::Deref;
        self.r#type.deref()
    }
    /// <p>The asset property definitions for this composite model.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.properties.is_none()`.
    pub fn properties(&self) -> &[crate::types::AssetModelProperty] {
        self.properties.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the asset model composite model.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The external ID of the asset model composite model. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-ids">Using external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn external_id(&self) -> ::std::option::Option<&str> {
        self.external_id.as_deref()
    }
}
impl AssetModelCompositeModel {
    /// Creates a new builder-style object to manufacture [`AssetModelCompositeModel`](crate::types::AssetModelCompositeModel).
    pub fn builder() -> crate::types::builders::AssetModelCompositeModelBuilder {
        crate::types::builders::AssetModelCompositeModelBuilder::default()
    }
}

/// A builder for [`AssetModelCompositeModel`](crate::types::AssetModelCompositeModel).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssetModelCompositeModelBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) properties: ::std::option::Option<::std::vec::Vec<crate::types::AssetModelProperty>>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) external_id: ::std::option::Option<::std::string::String>,
}
impl AssetModelCompositeModelBuilder {
    /// <p>The name of the composite model.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the composite model.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the composite model.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the composite model.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the composite model.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the composite model.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The type of the composite model. For alarm composite models, this type is <code>AWS/ALARM</code>.</p>
    /// This field is required.
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the composite model. For alarm composite models, this type is <code>AWS/ALARM</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the composite model. For alarm composite models, this type is <code>AWS/ALARM</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// Appends an item to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>The asset property definitions for this composite model.</p>
    pub fn properties(mut self, input: crate::types::AssetModelProperty) -> Self {
        let mut v = self.properties.unwrap_or_default();
        v.push(input);
        self.properties = ::std::option::Option::Some(v);
        self
    }
    /// <p>The asset property definitions for this composite model.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AssetModelProperty>>) -> Self {
        self.properties = input;
        self
    }
    /// <p>The asset property definitions for this composite model.</p>
    pub fn get_properties(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AssetModelProperty>> {
        &self.properties
    }
    /// <p>The ID of the asset model composite model.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset model composite model.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the asset model composite model.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The external ID of the asset model composite model. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-ids">Using external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn external_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.external_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The external ID of the asset model composite model. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-ids">Using external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_external_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.external_id = input;
        self
    }
    /// <p>The external ID of the asset model composite model. For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/object-ids.html#external-ids">Using external IDs</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_external_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.external_id
    }
    /// Consumes the builder and constructs a [`AssetModelCompositeModel`](crate::types::AssetModelCompositeModel).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::AssetModelCompositeModelBuilder::name)
    /// - [`r#type`](crate::types::builders::AssetModelCompositeModelBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::AssetModelCompositeModel, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AssetModelCompositeModel {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AssetModelCompositeModel",
                )
            })?,
            description: self.description,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building AssetModelCompositeModel",
                )
            })?,
            properties: self.properties,
            id: self.id,
            external_id: self.external_id,
        })
    }
}
