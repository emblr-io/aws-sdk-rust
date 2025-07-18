// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information on the adapter, including the adapter ID, Name, Creation time, and feature types.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AdapterOverview {
    /// <p>A unique identifier for the adapter resource.</p>
    pub adapter_id: ::std::option::Option<::std::string::String>,
    /// <p>A string naming the adapter resource.</p>
    pub adapter_name: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the adapter was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The feature types that the adapter is operating on.</p>
    pub feature_types: ::std::option::Option<::std::vec::Vec<crate::types::FeatureType>>,
}
impl AdapterOverview {
    /// <p>A unique identifier for the adapter resource.</p>
    pub fn adapter_id(&self) -> ::std::option::Option<&str> {
        self.adapter_id.as_deref()
    }
    /// <p>A string naming the adapter resource.</p>
    pub fn adapter_name(&self) -> ::std::option::Option<&str> {
        self.adapter_name.as_deref()
    }
    /// <p>The date and time that the adapter was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The feature types that the adapter is operating on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.feature_types.is_none()`.
    pub fn feature_types(&self) -> &[crate::types::FeatureType] {
        self.feature_types.as_deref().unwrap_or_default()
    }
}
impl AdapterOverview {
    /// Creates a new builder-style object to manufacture [`AdapterOverview`](crate::types::AdapterOverview).
    pub fn builder() -> crate::types::builders::AdapterOverviewBuilder {
        crate::types::builders::AdapterOverviewBuilder::default()
    }
}

/// A builder for [`AdapterOverview`](crate::types::AdapterOverview).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AdapterOverviewBuilder {
    pub(crate) adapter_id: ::std::option::Option<::std::string::String>,
    pub(crate) adapter_name: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) feature_types: ::std::option::Option<::std::vec::Vec<crate::types::FeatureType>>,
}
impl AdapterOverviewBuilder {
    /// <p>A unique identifier for the adapter resource.</p>
    pub fn adapter_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.adapter_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the adapter resource.</p>
    pub fn set_adapter_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.adapter_id = input;
        self
    }
    /// <p>A unique identifier for the adapter resource.</p>
    pub fn get_adapter_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.adapter_id
    }
    /// <p>A string naming the adapter resource.</p>
    pub fn adapter_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.adapter_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string naming the adapter resource.</p>
    pub fn set_adapter_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.adapter_name = input;
        self
    }
    /// <p>A string naming the adapter resource.</p>
    pub fn get_adapter_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.adapter_name
    }
    /// <p>The date and time that the adapter was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the adapter was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The date and time that the adapter was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// Appends an item to `feature_types`.
    ///
    /// To override the contents of this collection use [`set_feature_types`](Self::set_feature_types).
    ///
    /// <p>The feature types that the adapter is operating on.</p>
    pub fn feature_types(mut self, input: crate::types::FeatureType) -> Self {
        let mut v = self.feature_types.unwrap_or_default();
        v.push(input);
        self.feature_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The feature types that the adapter is operating on.</p>
    pub fn set_feature_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FeatureType>>) -> Self {
        self.feature_types = input;
        self
    }
    /// <p>The feature types that the adapter is operating on.</p>
    pub fn get_feature_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FeatureType>> {
        &self.feature_types
    }
    /// Consumes the builder and constructs a [`AdapterOverview`](crate::types::AdapterOverview).
    pub fn build(self) -> crate::types::AdapterOverview {
        crate::types::AdapterOverview {
            adapter_id: self.adapter_id,
            adapter_name: self.adapter_name,
            creation_time: self.creation_time,
            feature_types: self.feature_types,
        }
    }
}
