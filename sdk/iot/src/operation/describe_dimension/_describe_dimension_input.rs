// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDimensionInput {
    /// <p>The unique identifier for the dimension.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DescribeDimensionInput {
    /// <p>The unique identifier for the dimension.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DescribeDimensionInput {
    /// Creates a new builder-style object to manufacture [`DescribeDimensionInput`](crate::operation::describe_dimension::DescribeDimensionInput).
    pub fn builder() -> crate::operation::describe_dimension::builders::DescribeDimensionInputBuilder {
        crate::operation::describe_dimension::builders::DescribeDimensionInputBuilder::default()
    }
}

/// A builder for [`DescribeDimensionInput`](crate::operation::describe_dimension::DescribeDimensionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDimensionInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DescribeDimensionInputBuilder {
    /// <p>The unique identifier for the dimension.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the dimension.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The unique identifier for the dimension.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DescribeDimensionInput`](crate::operation::describe_dimension::DescribeDimensionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_dimension::DescribeDimensionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_dimension::DescribeDimensionInput { name: self.name })
    }
}
