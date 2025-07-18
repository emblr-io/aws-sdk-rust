// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains an Amazon Resource Name (ARN) and parameters that are associated with the rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Rule {
    /// <p>The type of attribute validation rule.</p>
    pub r#type: ::std::option::Option<crate::types::RuleType>,
    /// <p>The minimum and maximum parameters that are associated with the rule.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl Rule {
    /// <p>The type of attribute validation rule.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::RuleType> {
        self.r#type.as_ref()
    }
    /// <p>The minimum and maximum parameters that are associated with the rule.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.parameters.as_ref()
    }
}
impl Rule {
    /// Creates a new builder-style object to manufacture [`Rule`](crate::types::Rule).
    pub fn builder() -> crate::types::builders::RuleBuilder {
        crate::types::builders::RuleBuilder::default()
    }
}

/// A builder for [`Rule`](crate::types::Rule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::RuleType>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl RuleBuilder {
    /// <p>The type of attribute validation rule.</p>
    pub fn r#type(mut self, input: crate::types::RuleType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of attribute validation rule.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RuleType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of attribute validation rule.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RuleType> {
        &self.r#type
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The minimum and maximum parameters that are associated with the rule.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The minimum and maximum parameters that are associated with the rule.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The minimum and maximum parameters that are associated with the rule.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`Rule`](crate::types::Rule).
    pub fn build(self) -> crate::types::Rule {
        crate::types::Rule {
            r#type: self.r#type,
            parameters: self.parameters,
        }
    }
}
