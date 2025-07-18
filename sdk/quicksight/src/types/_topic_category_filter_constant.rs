// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A constant used in a category filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct TopicCategoryFilterConstant {
    /// <p>The type of category filter constant. This element is used to specify whether a constant is a singular or collective. Valid values are <code>SINGULAR</code> and <code>COLLECTIVE</code>.</p>
    pub constant_type: ::std::option::Option<crate::types::ConstantType>,
    /// <p>A singular constant used in a category filter. This element is used to specify a single value for the constant.</p>
    pub singular_constant: ::std::option::Option<::std::string::String>,
    /// <p>A collective constant used in a category filter. This element is used to specify a list of values for the constant.</p>
    pub collective_constant: ::std::option::Option<crate::types::CollectiveConstant>,
}
impl TopicCategoryFilterConstant {
    /// <p>The type of category filter constant. This element is used to specify whether a constant is a singular or collective. Valid values are <code>SINGULAR</code> and <code>COLLECTIVE</code>.</p>
    pub fn constant_type(&self) -> ::std::option::Option<&crate::types::ConstantType> {
        self.constant_type.as_ref()
    }
    /// <p>A singular constant used in a category filter. This element is used to specify a single value for the constant.</p>
    pub fn singular_constant(&self) -> ::std::option::Option<&str> {
        self.singular_constant.as_deref()
    }
    /// <p>A collective constant used in a category filter. This element is used to specify a list of values for the constant.</p>
    pub fn collective_constant(&self) -> ::std::option::Option<&crate::types::CollectiveConstant> {
        self.collective_constant.as_ref()
    }
}
impl ::std::fmt::Debug for TopicCategoryFilterConstant {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TopicCategoryFilterConstant");
        formatter.field("constant_type", &"*** Sensitive Data Redacted ***");
        formatter.field("singular_constant", &"*** Sensitive Data Redacted ***");
        formatter.field("collective_constant", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl TopicCategoryFilterConstant {
    /// Creates a new builder-style object to manufacture [`TopicCategoryFilterConstant`](crate::types::TopicCategoryFilterConstant).
    pub fn builder() -> crate::types::builders::TopicCategoryFilterConstantBuilder {
        crate::types::builders::TopicCategoryFilterConstantBuilder::default()
    }
}

/// A builder for [`TopicCategoryFilterConstant`](crate::types::TopicCategoryFilterConstant).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct TopicCategoryFilterConstantBuilder {
    pub(crate) constant_type: ::std::option::Option<crate::types::ConstantType>,
    pub(crate) singular_constant: ::std::option::Option<::std::string::String>,
    pub(crate) collective_constant: ::std::option::Option<crate::types::CollectiveConstant>,
}
impl TopicCategoryFilterConstantBuilder {
    /// <p>The type of category filter constant. This element is used to specify whether a constant is a singular or collective. Valid values are <code>SINGULAR</code> and <code>COLLECTIVE</code>.</p>
    pub fn constant_type(mut self, input: crate::types::ConstantType) -> Self {
        self.constant_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of category filter constant. This element is used to specify whether a constant is a singular or collective. Valid values are <code>SINGULAR</code> and <code>COLLECTIVE</code>.</p>
    pub fn set_constant_type(mut self, input: ::std::option::Option<crate::types::ConstantType>) -> Self {
        self.constant_type = input;
        self
    }
    /// <p>The type of category filter constant. This element is used to specify whether a constant is a singular or collective. Valid values are <code>SINGULAR</code> and <code>COLLECTIVE</code>.</p>
    pub fn get_constant_type(&self) -> &::std::option::Option<crate::types::ConstantType> {
        &self.constant_type
    }
    /// <p>A singular constant used in a category filter. This element is used to specify a single value for the constant.</p>
    pub fn singular_constant(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.singular_constant = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A singular constant used in a category filter. This element is used to specify a single value for the constant.</p>
    pub fn set_singular_constant(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.singular_constant = input;
        self
    }
    /// <p>A singular constant used in a category filter. This element is used to specify a single value for the constant.</p>
    pub fn get_singular_constant(&self) -> &::std::option::Option<::std::string::String> {
        &self.singular_constant
    }
    /// <p>A collective constant used in a category filter. This element is used to specify a list of values for the constant.</p>
    pub fn collective_constant(mut self, input: crate::types::CollectiveConstant) -> Self {
        self.collective_constant = ::std::option::Option::Some(input);
        self
    }
    /// <p>A collective constant used in a category filter. This element is used to specify a list of values for the constant.</p>
    pub fn set_collective_constant(mut self, input: ::std::option::Option<crate::types::CollectiveConstant>) -> Self {
        self.collective_constant = input;
        self
    }
    /// <p>A collective constant used in a category filter. This element is used to specify a list of values for the constant.</p>
    pub fn get_collective_constant(&self) -> &::std::option::Option<crate::types::CollectiveConstant> {
        &self.collective_constant
    }
    /// Consumes the builder and constructs a [`TopicCategoryFilterConstant`](crate::types::TopicCategoryFilterConstant).
    pub fn build(self) -> crate::types::TopicCategoryFilterConstant {
        crate::types::TopicCategoryFilterConstant {
            constant_type: self.constant_type,
            singular_constant: self.singular_constant,
            collective_constant: self.collective_constant,
        }
    }
}
impl ::std::fmt::Debug for TopicCategoryFilterConstantBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TopicCategoryFilterConstantBuilder");
        formatter.field("constant_type", &"*** Sensitive Data Redacted ***");
        formatter.field("singular_constant", &"*** Sensitive Data Redacted ***");
        formatter.field("collective_constant", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
