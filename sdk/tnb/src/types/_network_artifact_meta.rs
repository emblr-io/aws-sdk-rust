// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Metadata for network package artifacts.</p>
/// <p>Artifacts are the contents of the package descriptor file and the state of the package.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkArtifactMeta {
    /// <p>Lists network package overrides.</p>
    pub overrides: ::std::option::Option<::std::vec::Vec<crate::types::ToscaOverride>>,
}
impl NetworkArtifactMeta {
    /// <p>Lists network package overrides.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.overrides.is_none()`.
    pub fn overrides(&self) -> &[crate::types::ToscaOverride] {
        self.overrides.as_deref().unwrap_or_default()
    }
}
impl NetworkArtifactMeta {
    /// Creates a new builder-style object to manufacture [`NetworkArtifactMeta`](crate::types::NetworkArtifactMeta).
    pub fn builder() -> crate::types::builders::NetworkArtifactMetaBuilder {
        crate::types::builders::NetworkArtifactMetaBuilder::default()
    }
}

/// A builder for [`NetworkArtifactMeta`](crate::types::NetworkArtifactMeta).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkArtifactMetaBuilder {
    pub(crate) overrides: ::std::option::Option<::std::vec::Vec<crate::types::ToscaOverride>>,
}
impl NetworkArtifactMetaBuilder {
    /// Appends an item to `overrides`.
    ///
    /// To override the contents of this collection use [`set_overrides`](Self::set_overrides).
    ///
    /// <p>Lists network package overrides.</p>
    pub fn overrides(mut self, input: crate::types::ToscaOverride) -> Self {
        let mut v = self.overrides.unwrap_or_default();
        v.push(input);
        self.overrides = ::std::option::Option::Some(v);
        self
    }
    /// <p>Lists network package overrides.</p>
    pub fn set_overrides(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ToscaOverride>>) -> Self {
        self.overrides = input;
        self
    }
    /// <p>Lists network package overrides.</p>
    pub fn get_overrides(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ToscaOverride>> {
        &self.overrides
    }
    /// Consumes the builder and constructs a [`NetworkArtifactMeta`](crate::types::NetworkArtifactMeta).
    pub fn build(self) -> crate::types::NetworkArtifactMeta {
        crate::types::NetworkArtifactMeta { overrides: self.overrides }
    }
}
