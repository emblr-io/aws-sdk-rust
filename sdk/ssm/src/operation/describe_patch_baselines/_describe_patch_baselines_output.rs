// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribePatchBaselinesOutput {
    /// <p>An array of <code>PatchBaselineIdentity</code> elements.</p>
    pub baseline_identities: ::std::option::Option<::std::vec::Vec<crate::types::PatchBaselineIdentity>>,
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribePatchBaselinesOutput {
    /// <p>An array of <code>PatchBaselineIdentity</code> elements.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.baseline_identities.is_none()`.
    pub fn baseline_identities(&self) -> &[crate::types::PatchBaselineIdentity] {
        self.baseline_identities.as_deref().unwrap_or_default()
    }
    /// <p>The token to use when requesting the next set of items. If there are no additional items to return, the string is empty.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribePatchBaselinesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribePatchBaselinesOutput {
    /// Creates a new builder-style object to manufacture [`DescribePatchBaselinesOutput`](crate::operation::describe_patch_baselines::DescribePatchBaselinesOutput).
    pub fn builder() -> crate::operation::describe_patch_baselines::builders::DescribePatchBaselinesOutputBuilder {
        crate::operation::describe_patch_baselines::builders::DescribePatchBaselinesOutputBuilder::default()
    }
}

/// A builder for [`DescribePatchBaselinesOutput`](crate::operation::describe_patch_baselines::DescribePatchBaselinesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribePatchBaselinesOutputBuilder {
    pub(crate) baseline_identities: ::std::option::Option<::std::vec::Vec<crate::types::PatchBaselineIdentity>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribePatchBaselinesOutputBuilder {
    /// Appends an item to `baseline_identities`.
    ///
    /// To override the contents of this collection use [`set_baseline_identities`](Self::set_baseline_identities).
    ///
    /// <p>An array of <code>PatchBaselineIdentity</code> elements.</p>
    pub fn baseline_identities(mut self, input: crate::types::PatchBaselineIdentity) -> Self {
        let mut v = self.baseline_identities.unwrap_or_default();
        v.push(input);
        self.baseline_identities = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>PatchBaselineIdentity</code> elements.</p>
    pub fn set_baseline_identities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PatchBaselineIdentity>>) -> Self {
        self.baseline_identities = input;
        self
    }
    /// <p>An array of <code>PatchBaselineIdentity</code> elements.</p>
    pub fn get_baseline_identities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PatchBaselineIdentity>> {
        &self.baseline_identities
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
    /// Consumes the builder and constructs a [`DescribePatchBaselinesOutput`](crate::operation::describe_patch_baselines::DescribePatchBaselinesOutput).
    pub fn build(self) -> crate::operation::describe_patch_baselines::DescribePatchBaselinesOutput {
        crate::operation::describe_patch_baselines::DescribePatchBaselinesOutput {
            baseline_identities: self.baseline_identities,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
