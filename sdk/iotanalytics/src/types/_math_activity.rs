// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An activity that computes an arithmetic expression using the message's attributes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MathActivity {
    /// <p>The name of the math activity.</p>
    pub name: ::std::string::String,
    /// <p>The name of the attribute that contains the result of the math operation.</p>
    pub attribute: ::std::string::String,
    /// <p>An expression that uses one or more existing attributes and must return an integer value.</p>
    pub math: ::std::string::String,
    /// <p>The next activity in the pipeline.</p>
    pub next: ::std::option::Option<::std::string::String>,
}
impl MathActivity {
    /// <p>The name of the math activity.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The name of the attribute that contains the result of the math operation.</p>
    pub fn attribute(&self) -> &str {
        use std::ops::Deref;
        self.attribute.deref()
    }
    /// <p>An expression that uses one or more existing attributes and must return an integer value.</p>
    pub fn math(&self) -> &str {
        use std::ops::Deref;
        self.math.deref()
    }
    /// <p>The next activity in the pipeline.</p>
    pub fn next(&self) -> ::std::option::Option<&str> {
        self.next.as_deref()
    }
}
impl MathActivity {
    /// Creates a new builder-style object to manufacture [`MathActivity`](crate::types::MathActivity).
    pub fn builder() -> crate::types::builders::MathActivityBuilder {
        crate::types::builders::MathActivityBuilder::default()
    }
}

/// A builder for [`MathActivity`](crate::types::MathActivity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MathActivityBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) attribute: ::std::option::Option<::std::string::String>,
    pub(crate) math: ::std::option::Option<::std::string::String>,
    pub(crate) next: ::std::option::Option<::std::string::String>,
}
impl MathActivityBuilder {
    /// <p>The name of the math activity.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the math activity.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the math activity.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The name of the attribute that contains the result of the math operation.</p>
    /// This field is required.
    pub fn attribute(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the attribute that contains the result of the math operation.</p>
    pub fn set_attribute(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute = input;
        self
    }
    /// <p>The name of the attribute that contains the result of the math operation.</p>
    pub fn get_attribute(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute
    }
    /// <p>An expression that uses one or more existing attributes and must return an integer value.</p>
    /// This field is required.
    pub fn math(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.math = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An expression that uses one or more existing attributes and must return an integer value.</p>
    pub fn set_math(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.math = input;
        self
    }
    /// <p>An expression that uses one or more existing attributes and must return an integer value.</p>
    pub fn get_math(&self) -> &::std::option::Option<::std::string::String> {
        &self.math
    }
    /// <p>The next activity in the pipeline.</p>
    pub fn next(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next activity in the pipeline.</p>
    pub fn set_next(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next = input;
        self
    }
    /// <p>The next activity in the pipeline.</p>
    pub fn get_next(&self) -> &::std::option::Option<::std::string::String> {
        &self.next
    }
    /// Consumes the builder and constructs a [`MathActivity`](crate::types::MathActivity).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::MathActivityBuilder::name)
    /// - [`attribute`](crate::types::builders::MathActivityBuilder::attribute)
    /// - [`math`](crate::types::builders::MathActivityBuilder::math)
    pub fn build(self) -> ::std::result::Result<crate::types::MathActivity, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MathActivity {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building MathActivity",
                )
            })?,
            attribute: self.attribute.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute",
                    "attribute was not specified but it is required when building MathActivity",
                )
            })?,
            math: self.math.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "math",
                    "math was not specified but it is required when building MathActivity",
                )
            })?,
            next: self.next,
        })
    }
}
