// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing the details of an update to a taints payload. For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/node-taints-managed-node-groups.html">Node taints on managed node groups</a> in the <i>Amazon EKS User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTaintsPayload {
    /// <p>Kubernetes taints to be added or updated.</p>
    pub add_or_update_taints: ::std::option::Option<::std::vec::Vec<crate::types::Taint>>,
    /// <p>Kubernetes taints to remove.</p>
    pub remove_taints: ::std::option::Option<::std::vec::Vec<crate::types::Taint>>,
}
impl UpdateTaintsPayload {
    /// <p>Kubernetes taints to be added or updated.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.add_or_update_taints.is_none()`.
    pub fn add_or_update_taints(&self) -> &[crate::types::Taint] {
        self.add_or_update_taints.as_deref().unwrap_or_default()
    }
    /// <p>Kubernetes taints to remove.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.remove_taints.is_none()`.
    pub fn remove_taints(&self) -> &[crate::types::Taint] {
        self.remove_taints.as_deref().unwrap_or_default()
    }
}
impl UpdateTaintsPayload {
    /// Creates a new builder-style object to manufacture [`UpdateTaintsPayload`](crate::types::UpdateTaintsPayload).
    pub fn builder() -> crate::types::builders::UpdateTaintsPayloadBuilder {
        crate::types::builders::UpdateTaintsPayloadBuilder::default()
    }
}

/// A builder for [`UpdateTaintsPayload`](crate::types::UpdateTaintsPayload).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTaintsPayloadBuilder {
    pub(crate) add_or_update_taints: ::std::option::Option<::std::vec::Vec<crate::types::Taint>>,
    pub(crate) remove_taints: ::std::option::Option<::std::vec::Vec<crate::types::Taint>>,
}
impl UpdateTaintsPayloadBuilder {
    /// Appends an item to `add_or_update_taints`.
    ///
    /// To override the contents of this collection use [`set_add_or_update_taints`](Self::set_add_or_update_taints).
    ///
    /// <p>Kubernetes taints to be added or updated.</p>
    pub fn add_or_update_taints(mut self, input: crate::types::Taint) -> Self {
        let mut v = self.add_or_update_taints.unwrap_or_default();
        v.push(input);
        self.add_or_update_taints = ::std::option::Option::Some(v);
        self
    }
    /// <p>Kubernetes taints to be added or updated.</p>
    pub fn set_add_or_update_taints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Taint>>) -> Self {
        self.add_or_update_taints = input;
        self
    }
    /// <p>Kubernetes taints to be added or updated.</p>
    pub fn get_add_or_update_taints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Taint>> {
        &self.add_or_update_taints
    }
    /// Appends an item to `remove_taints`.
    ///
    /// To override the contents of this collection use [`set_remove_taints`](Self::set_remove_taints).
    ///
    /// <p>Kubernetes taints to remove.</p>
    pub fn remove_taints(mut self, input: crate::types::Taint) -> Self {
        let mut v = self.remove_taints.unwrap_or_default();
        v.push(input);
        self.remove_taints = ::std::option::Option::Some(v);
        self
    }
    /// <p>Kubernetes taints to remove.</p>
    pub fn set_remove_taints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Taint>>) -> Self {
        self.remove_taints = input;
        self
    }
    /// <p>Kubernetes taints to remove.</p>
    pub fn get_remove_taints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Taint>> {
        &self.remove_taints
    }
    /// Consumes the builder and constructs a [`UpdateTaintsPayload`](crate::types::UpdateTaintsPayload).
    pub fn build(self) -> crate::types::UpdateTaintsPayload {
        crate::types::UpdateTaintsPayload {
            add_or_update_taints: self.add_or_update_taints,
            remove_taints: self.remove_taints,
        }
    }
}
