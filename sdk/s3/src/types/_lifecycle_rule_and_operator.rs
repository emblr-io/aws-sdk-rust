// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This is used in a Lifecycle Rule Filter to apply a logical AND to two or more predicates. The Lifecycle Rule will apply to any object matching all of the predicates configured inside the And operator.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LifecycleRuleAndOperator {
    /// <p>Prefix identifying one or more objects to which the rule applies.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>All of these tags must exist in the object's tag set in order for the rule to apply.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Minimum object size to which the rule applies.</p>
    pub object_size_greater_than: ::std::option::Option<i64>,
    /// <p>Maximum object size to which the rule applies.</p>
    pub object_size_less_than: ::std::option::Option<i64>,
}
impl LifecycleRuleAndOperator {
    /// <p>Prefix identifying one or more objects to which the rule applies.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>All of these tags must exist in the object's tag set in order for the rule to apply.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Minimum object size to which the rule applies.</p>
    pub fn object_size_greater_than(&self) -> ::std::option::Option<i64> {
        self.object_size_greater_than
    }
    /// <p>Maximum object size to which the rule applies.</p>
    pub fn object_size_less_than(&self) -> ::std::option::Option<i64> {
        self.object_size_less_than
    }
}
impl LifecycleRuleAndOperator {
    /// Creates a new builder-style object to manufacture [`LifecycleRuleAndOperator`](crate::types::LifecycleRuleAndOperator).
    pub fn builder() -> crate::types::builders::LifecycleRuleAndOperatorBuilder {
        crate::types::builders::LifecycleRuleAndOperatorBuilder::default()
    }
}

/// A builder for [`LifecycleRuleAndOperator`](crate::types::LifecycleRuleAndOperator).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LifecycleRuleAndOperatorBuilder {
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) object_size_greater_than: ::std::option::Option<i64>,
    pub(crate) object_size_less_than: ::std::option::Option<i64>,
}
impl LifecycleRuleAndOperatorBuilder {
    /// <p>Prefix identifying one or more objects to which the rule applies.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Prefix identifying one or more objects to which the rule applies.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>Prefix identifying one or more objects to which the rule applies.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>All of these tags must exist in the object's tag set in order for the rule to apply.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>All of these tags must exist in the object's tag set in order for the rule to apply.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>All of these tags must exist in the object's tag set in order for the rule to apply.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>Minimum object size to which the rule applies.</p>
    pub fn object_size_greater_than(mut self, input: i64) -> Self {
        self.object_size_greater_than = ::std::option::Option::Some(input);
        self
    }
    /// <p>Minimum object size to which the rule applies.</p>
    pub fn set_object_size_greater_than(mut self, input: ::std::option::Option<i64>) -> Self {
        self.object_size_greater_than = input;
        self
    }
    /// <p>Minimum object size to which the rule applies.</p>
    pub fn get_object_size_greater_than(&self) -> &::std::option::Option<i64> {
        &self.object_size_greater_than
    }
    /// <p>Maximum object size to which the rule applies.</p>
    pub fn object_size_less_than(mut self, input: i64) -> Self {
        self.object_size_less_than = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum object size to which the rule applies.</p>
    pub fn set_object_size_less_than(mut self, input: ::std::option::Option<i64>) -> Self {
        self.object_size_less_than = input;
        self
    }
    /// <p>Maximum object size to which the rule applies.</p>
    pub fn get_object_size_less_than(&self) -> &::std::option::Option<i64> {
        &self.object_size_less_than
    }
    /// Consumes the builder and constructs a [`LifecycleRuleAndOperator`](crate::types::LifecycleRuleAndOperator).
    pub fn build(self) -> crate::types::LifecycleRuleAndOperator {
        crate::types::LifecycleRuleAndOperator {
            prefix: self.prefix,
            tags: self.tags,
            object_size_greater_than: self.object_size_greater_than,
            object_size_less_than: self.object_size_less_than,
        }
    }
}
