// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a destination.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Destinations {
    /// <p>The Amazon Resource Name of the resource.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the resource.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of value in <code>Expression</code>.</p>
    pub expression_type: ::std::option::Option<crate::types::ExpressionType>,
    /// <p>The rule name or topic rule to send messages to.</p>
    pub expression: ::std::option::Option<::std::string::String>,
    /// <p>The description of the resource.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the IAM Role that authorizes the destination.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
}
impl Destinations {
    /// <p>The Amazon Resource Name of the resource.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the resource.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of value in <code>Expression</code>.</p>
    pub fn expression_type(&self) -> ::std::option::Option<&crate::types::ExpressionType> {
        self.expression_type.as_ref()
    }
    /// <p>The rule name or topic rule to send messages to.</p>
    pub fn expression(&self) -> ::std::option::Option<&str> {
        self.expression.as_deref()
    }
    /// <p>The description of the resource.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ARN of the IAM Role that authorizes the destination.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
}
impl Destinations {
    /// Creates a new builder-style object to manufacture [`Destinations`](crate::types::Destinations).
    pub fn builder() -> crate::types::builders::DestinationsBuilder {
        crate::types::builders::DestinationsBuilder::default()
    }
}

/// A builder for [`Destinations`](crate::types::Destinations).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DestinationsBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) expression_type: ::std::option::Option<crate::types::ExpressionType>,
    pub(crate) expression: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl DestinationsBuilder {
    /// <p>The Amazon Resource Name of the resource.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name of the resource.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name of the resource.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the resource.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the resource.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of value in <code>Expression</code>.</p>
    pub fn expression_type(mut self, input: crate::types::ExpressionType) -> Self {
        self.expression_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of value in <code>Expression</code>.</p>
    pub fn set_expression_type(mut self, input: ::std::option::Option<crate::types::ExpressionType>) -> Self {
        self.expression_type = input;
        self
    }
    /// <p>The type of value in <code>Expression</code>.</p>
    pub fn get_expression_type(&self) -> &::std::option::Option<crate::types::ExpressionType> {
        &self.expression_type
    }
    /// <p>The rule name or topic rule to send messages to.</p>
    pub fn expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule name or topic rule to send messages to.</p>
    pub fn set_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression = input;
        self
    }
    /// <p>The rule name or topic rule to send messages to.</p>
    pub fn get_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression
    }
    /// <p>The description of the resource.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the resource.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the resource.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The ARN of the IAM Role that authorizes the destination.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM Role that authorizes the destination.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The ARN of the IAM Role that authorizes the destination.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`Destinations`](crate::types::Destinations).
    pub fn build(self) -> crate::types::Destinations {
        crate::types::Destinations {
            arn: self.arn,
            name: self.name,
            expression_type: self.expression_type,
            expression: self.expression,
            description: self.description,
            role_arn: self.role_arn,
        }
    }
}
