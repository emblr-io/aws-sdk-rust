// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A property that allows a node to repel a <code>Pod</code>. For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/node-taints-managed-node-groups.html">Node taints on managed node groups</a> in the <i>Amazon EKS User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Taint {
    /// <p>The key of the taint.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>The value of the taint.</p>
    pub value: ::std::option::Option<::std::string::String>,
    /// <p>The effect of the taint.</p>
    pub effect: ::std::option::Option<crate::types::TaintEffect>,
}
impl Taint {
    /// <p>The key of the taint.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>The value of the taint.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
    /// <p>The effect of the taint.</p>
    pub fn effect(&self) -> ::std::option::Option<&crate::types::TaintEffect> {
        self.effect.as_ref()
    }
}
impl Taint {
    /// Creates a new builder-style object to manufacture [`Taint`](crate::types::Taint).
    pub fn builder() -> crate::types::builders::TaintBuilder {
        crate::types::builders::TaintBuilder::default()
    }
}

/// A builder for [`Taint`](crate::types::Taint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaintBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) effect: ::std::option::Option<crate::types::TaintEffect>,
}
impl TaintBuilder {
    /// <p>The key of the taint.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key of the taint.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The key of the taint.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>The value of the taint.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the taint.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the taint.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The effect of the taint.</p>
    pub fn effect(mut self, input: crate::types::TaintEffect) -> Self {
        self.effect = ::std::option::Option::Some(input);
        self
    }
    /// <p>The effect of the taint.</p>
    pub fn set_effect(mut self, input: ::std::option::Option<crate::types::TaintEffect>) -> Self {
        self.effect = input;
        self
    }
    /// <p>The effect of the taint.</p>
    pub fn get_effect(&self) -> &::std::option::Option<crate::types::TaintEffect> {
        &self.effect
    }
    /// Consumes the builder and constructs a [`Taint`](crate::types::Taint).
    pub fn build(self) -> crate::types::Taint {
        crate::types::Taint {
            key: self.key,
            value: self.value,
            effect: self.effect,
        }
    }
}
