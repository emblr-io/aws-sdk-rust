// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration of loading animation in free-form layout.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LoadingAnimation {
    /// <p>The visibility configuration of <code>LoadingAnimation</code>.</p>
    pub visibility: ::std::option::Option<crate::types::Visibility>,
}
impl LoadingAnimation {
    /// <p>The visibility configuration of <code>LoadingAnimation</code>.</p>
    pub fn visibility(&self) -> ::std::option::Option<&crate::types::Visibility> {
        self.visibility.as_ref()
    }
}
impl LoadingAnimation {
    /// Creates a new builder-style object to manufacture [`LoadingAnimation`](crate::types::LoadingAnimation).
    pub fn builder() -> crate::types::builders::LoadingAnimationBuilder {
        crate::types::builders::LoadingAnimationBuilder::default()
    }
}

/// A builder for [`LoadingAnimation`](crate::types::LoadingAnimation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LoadingAnimationBuilder {
    pub(crate) visibility: ::std::option::Option<crate::types::Visibility>,
}
impl LoadingAnimationBuilder {
    /// <p>The visibility configuration of <code>LoadingAnimation</code>.</p>
    pub fn visibility(mut self, input: crate::types::Visibility) -> Self {
        self.visibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>The visibility configuration of <code>LoadingAnimation</code>.</p>
    pub fn set_visibility(mut self, input: ::std::option::Option<crate::types::Visibility>) -> Self {
        self.visibility = input;
        self
    }
    /// <p>The visibility configuration of <code>LoadingAnimation</code>.</p>
    pub fn get_visibility(&self) -> &::std::option::Option<crate::types::Visibility> {
        &self.visibility
    }
    /// Consumes the builder and constructs a [`LoadingAnimation`](crate::types::LoadingAnimation).
    pub fn build(self) -> crate::types::LoadingAnimation {
        crate::types::LoadingAnimation { visibility: self.visibility }
    }
}
