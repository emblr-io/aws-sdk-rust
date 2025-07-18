// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies which files, folders, and objects to include or exclude when transferring files from source to destination.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilterRule {
    /// <p>The type of filter rule to apply. DataSync only supports the SIMPLE_PATTERN rule type.</p>
    pub filter_type: ::std::option::Option<crate::types::FilterType>,
    /// <p>A single filter string that consists of the patterns to include or exclude. The patterns are delimited by "|" (that is, a pipe), for example: <code>/folder1|/folder2</code></p>
    /// <p></p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl FilterRule {
    /// <p>The type of filter rule to apply. DataSync only supports the SIMPLE_PATTERN rule type.</p>
    pub fn filter_type(&self) -> ::std::option::Option<&crate::types::FilterType> {
        self.filter_type.as_ref()
    }
    /// <p>A single filter string that consists of the patterns to include or exclude. The patterns are delimited by "|" (that is, a pipe), for example: <code>/folder1|/folder2</code></p>
    /// <p></p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl FilterRule {
    /// Creates a new builder-style object to manufacture [`FilterRule`](crate::types::FilterRule).
    pub fn builder() -> crate::types::builders::FilterRuleBuilder {
        crate::types::builders::FilterRuleBuilder::default()
    }
}

/// A builder for [`FilterRule`](crate::types::FilterRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterRuleBuilder {
    pub(crate) filter_type: ::std::option::Option<crate::types::FilterType>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl FilterRuleBuilder {
    /// <p>The type of filter rule to apply. DataSync only supports the SIMPLE_PATTERN rule type.</p>
    pub fn filter_type(mut self, input: crate::types::FilterType) -> Self {
        self.filter_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of filter rule to apply. DataSync only supports the SIMPLE_PATTERN rule type.</p>
    pub fn set_filter_type(mut self, input: ::std::option::Option<crate::types::FilterType>) -> Self {
        self.filter_type = input;
        self
    }
    /// <p>The type of filter rule to apply. DataSync only supports the SIMPLE_PATTERN rule type.</p>
    pub fn get_filter_type(&self) -> &::std::option::Option<crate::types::FilterType> {
        &self.filter_type
    }
    /// <p>A single filter string that consists of the patterns to include or exclude. The patterns are delimited by "|" (that is, a pipe), for example: <code>/folder1|/folder2</code></p>
    /// <p></p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A single filter string that consists of the patterns to include or exclude. The patterns are delimited by "|" (that is, a pipe), for example: <code>/folder1|/folder2</code></p>
    /// <p></p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>A single filter string that consists of the patterns to include or exclude. The patterns are delimited by "|" (that is, a pipe), for example: <code>/folder1|/folder2</code></p>
    /// <p></p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`FilterRule`](crate::types::FilterRule).
    pub fn build(self) -> crate::types::FilterRule {
        crate::types::FilterRule {
            filter_type: self.filter_type,
            value: self.value,
        }
    }
}
