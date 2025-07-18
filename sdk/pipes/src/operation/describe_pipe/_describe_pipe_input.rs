// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribePipeInput {
    /// <p>The name of the pipe.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DescribePipeInput {
    /// <p>The name of the pipe.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DescribePipeInput {
    /// Creates a new builder-style object to manufacture [`DescribePipeInput`](crate::operation::describe_pipe::DescribePipeInput).
    pub fn builder() -> crate::operation::describe_pipe::builders::DescribePipeInputBuilder {
        crate::operation::describe_pipe::builders::DescribePipeInputBuilder::default()
    }
}

/// A builder for [`DescribePipeInput`](crate::operation::describe_pipe::DescribePipeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribePipeInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DescribePipeInputBuilder {
    /// <p>The name of the pipe.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the pipe.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the pipe.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DescribePipeInput`](crate::operation::describe_pipe::DescribePipeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_pipe::DescribePipeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_pipe::DescribePipeInput { name: self.name })
    }
}
