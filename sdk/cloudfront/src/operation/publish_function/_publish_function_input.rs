// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PublishFunctionInput {
    /// <p>The name of the function that you are publishing.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The current version (<code>ETag</code> value) of the function that you are publishing, which you can get using <code>DescribeFunction</code>.</p>
    pub if_match: ::std::option::Option<::std::string::String>,
}
impl PublishFunctionInput {
    /// <p>The name of the function that you are publishing.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The current version (<code>ETag</code> value) of the function that you are publishing, which you can get using <code>DescribeFunction</code>.</p>
    pub fn if_match(&self) -> ::std::option::Option<&str> {
        self.if_match.as_deref()
    }
}
impl PublishFunctionInput {
    /// Creates a new builder-style object to manufacture [`PublishFunctionInput`](crate::operation::publish_function::PublishFunctionInput).
    pub fn builder() -> crate::operation::publish_function::builders::PublishFunctionInputBuilder {
        crate::operation::publish_function::builders::PublishFunctionInputBuilder::default()
    }
}

/// A builder for [`PublishFunctionInput`](crate::operation::publish_function::PublishFunctionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PublishFunctionInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) if_match: ::std::option::Option<::std::string::String>,
}
impl PublishFunctionInputBuilder {
    /// <p>The name of the function that you are publishing.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the function that you are publishing.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the function that you are publishing.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The current version (<code>ETag</code> value) of the function that you are publishing, which you can get using <code>DescribeFunction</code>.</p>
    /// This field is required.
    pub fn if_match(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.if_match = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version (<code>ETag</code> value) of the function that you are publishing, which you can get using <code>DescribeFunction</code>.</p>
    pub fn set_if_match(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.if_match = input;
        self
    }
    /// <p>The current version (<code>ETag</code> value) of the function that you are publishing, which you can get using <code>DescribeFunction</code>.</p>
    pub fn get_if_match(&self) -> &::std::option::Option<::std::string::String> {
        &self.if_match
    }
    /// Consumes the builder and constructs a [`PublishFunctionInput`](crate::operation::publish_function::PublishFunctionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::publish_function::PublishFunctionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::publish_function::PublishFunctionInput {
            name: self.name,
            if_match: self.if_match,
        })
    }
}
