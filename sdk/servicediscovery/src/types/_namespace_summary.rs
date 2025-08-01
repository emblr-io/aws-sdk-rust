// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains information about a namespace.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NamespaceSummary {
    /// <p>The ID of the namespace.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) that Cloud Map assigns to the namespace when you create it.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the namespace. When you create a namespace, Cloud Map automatically creates a Route&nbsp;53 hosted zone that has the same name as the namespace.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of the namespace, either public or private.</p>
    pub r#type: ::std::option::Option<crate::types::NamespaceType>,
    /// <p>A description for the namespace.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The number of services that were created using the namespace.</p>
    pub service_count: ::std::option::Option<i32>,
    /// <p>The properties of the namespace.</p>
    pub properties: ::std::option::Option<crate::types::NamespaceProperties>,
    /// <p>The date and time that the namespace was created.</p>
    pub create_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl NamespaceSummary {
    /// <p>The ID of the namespace.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) that Cloud Map assigns to the namespace when you create it.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the namespace. When you create a namespace, Cloud Map automatically creates a Route&nbsp;53 hosted zone that has the same name as the namespace.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of the namespace, either public or private.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::NamespaceType> {
        self.r#type.as_ref()
    }
    /// <p>A description for the namespace.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The number of services that were created using the namespace.</p>
    pub fn service_count(&self) -> ::std::option::Option<i32> {
        self.service_count
    }
    /// <p>The properties of the namespace.</p>
    pub fn properties(&self) -> ::std::option::Option<&crate::types::NamespaceProperties> {
        self.properties.as_ref()
    }
    /// <p>The date and time that the namespace was created.</p>
    pub fn create_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_date.as_ref()
    }
}
impl NamespaceSummary {
    /// Creates a new builder-style object to manufacture [`NamespaceSummary`](crate::types::NamespaceSummary).
    pub fn builder() -> crate::types::builders::NamespaceSummaryBuilder {
        crate::types::builders::NamespaceSummaryBuilder::default()
    }
}

/// A builder for [`NamespaceSummary`](crate::types::NamespaceSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NamespaceSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::NamespaceType>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) service_count: ::std::option::Option<i32>,
    pub(crate) properties: ::std::option::Option<crate::types::NamespaceProperties>,
    pub(crate) create_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl NamespaceSummaryBuilder {
    /// <p>The ID of the namespace.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the namespace.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the namespace.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) that Cloud Map assigns to the namespace when you create it.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that Cloud Map assigns to the namespace when you create it.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that Cloud Map assigns to the namespace when you create it.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the namespace. When you create a namespace, Cloud Map automatically creates a Route&nbsp;53 hosted zone that has the same name as the namespace.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the namespace. When you create a namespace, Cloud Map automatically creates a Route&nbsp;53 hosted zone that has the same name as the namespace.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the namespace. When you create a namespace, Cloud Map automatically creates a Route&nbsp;53 hosted zone that has the same name as the namespace.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of the namespace, either public or private.</p>
    pub fn r#type(mut self, input: crate::types::NamespaceType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the namespace, either public or private.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::NamespaceType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the namespace, either public or private.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::NamespaceType> {
        &self.r#type
    }
    /// <p>A description for the namespace.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the namespace.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the namespace.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The number of services that were created using the namespace.</p>
    pub fn service_count(mut self, input: i32) -> Self {
        self.service_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of services that were created using the namespace.</p>
    pub fn set_service_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.service_count = input;
        self
    }
    /// <p>The number of services that were created using the namespace.</p>
    pub fn get_service_count(&self) -> &::std::option::Option<i32> {
        &self.service_count
    }
    /// <p>The properties of the namespace.</p>
    pub fn properties(mut self, input: crate::types::NamespaceProperties) -> Self {
        self.properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties of the namespace.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<crate::types::NamespaceProperties>) -> Self {
        self.properties = input;
        self
    }
    /// <p>The properties of the namespace.</p>
    pub fn get_properties(&self) -> &::std::option::Option<crate::types::NamespaceProperties> {
        &self.properties
    }
    /// <p>The date and time that the namespace was created.</p>
    pub fn create_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the namespace was created.</p>
    pub fn set_create_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_date = input;
        self
    }
    /// <p>The date and time that the namespace was created.</p>
    pub fn get_create_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_date
    }
    /// Consumes the builder and constructs a [`NamespaceSummary`](crate::types::NamespaceSummary).
    pub fn build(self) -> crate::types::NamespaceSummary {
        crate::types::NamespaceSummary {
            id: self.id,
            arn: self.arn,
            name: self.name,
            r#type: self.r#type,
            description: self.description,
            service_count: self.service_count,
            properties: self.properties,
            create_date: self.create_date,
        }
    }
}
