// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeEffectivePatchesForPatchBaselineOutput {
    /// <p>An array of patches and patch status.</p>
    pub effective_patches: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePatch>>,
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeEffectivePatchesForPatchBaselineOutput {
    /// <p>An array of patches and patch status.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.effective_patches.is_none()`.
    pub fn effective_patches(&self) -> &[crate::types::EffectivePatch] {
        self.effective_patches.as_deref().unwrap_or_default()
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeEffectivePatchesForPatchBaselineOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeEffectivePatchesForPatchBaselineOutput {
    /// Creates a new builder-style object to manufacture [`DescribeEffectivePatchesForPatchBaselineOutput`](crate::operation::describe_effective_patches_for_patch_baseline::DescribeEffectivePatchesForPatchBaselineOutput).
    pub fn builder(
    ) -> crate::operation::describe_effective_patches_for_patch_baseline::builders::DescribeEffectivePatchesForPatchBaselineOutputBuilder {
        crate::operation::describe_effective_patches_for_patch_baseline::builders::DescribeEffectivePatchesForPatchBaselineOutputBuilder::default()
    }
}

/// A builder for [`DescribeEffectivePatchesForPatchBaselineOutput`](crate::operation::describe_effective_patches_for_patch_baseline::DescribeEffectivePatchesForPatchBaselineOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeEffectivePatchesForPatchBaselineOutputBuilder {
    pub(crate) effective_patches: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePatch>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeEffectivePatchesForPatchBaselineOutputBuilder {
    /// Appends an item to `effective_patches`.
    ///
    /// To override the contents of this collection use [`set_effective_patches`](Self::set_effective_patches).
    ///
    /// <p>An array of patches and patch status.</p>
    pub fn effective_patches(mut self, input: crate::types::EffectivePatch) -> Self {
        let mut v = self.effective_patches.unwrap_or_default();
        v.push(input);
        self.effective_patches = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of patches and patch status.</p>
    pub fn set_effective_patches(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePatch>>) -> Self {
        self.effective_patches = input;
        self
    }
    /// <p>An array of patches and patch status.</p>
    pub fn get_effective_patches(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EffectivePatch>> {
        &self.effective_patches
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeEffectivePatchesForPatchBaselineOutput`](crate::operation::describe_effective_patches_for_patch_baseline::DescribeEffectivePatchesForPatchBaselineOutput).
    pub fn build(self) -> crate::operation::describe_effective_patches_for_patch_baseline::DescribeEffectivePatchesForPatchBaselineOutput {
        crate::operation::describe_effective_patches_for_patch_baseline::DescribeEffectivePatchesForPatchBaselineOutput {
            effective_patches: self.effective_patches,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
