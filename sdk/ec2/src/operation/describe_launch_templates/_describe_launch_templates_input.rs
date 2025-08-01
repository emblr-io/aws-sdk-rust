// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLaunchTemplatesInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>One or more launch template IDs.</p>
    pub launch_template_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>One or more launch template names.</p>
    pub launch_template_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The time the launch template was created.</p></li>
    /// <li>
    /// <p><code>launch-template-name</code> - The name of the launch template.</p></li>
    /// <li>
    /// <p><code>tag</code>:<key>
    /// - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key
    /// <code>Owner</code> and the value
    /// <code>TeamA</code>, specify
    /// <code>tag:Owner</code> for the filter name and
    /// <code>TeamA</code> for the filter value.
    /// </key></p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The token to request the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 1 and 200.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl DescribeLaunchTemplatesInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>One or more launch template IDs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.launch_template_ids.is_none()`.
    pub fn launch_template_ids(&self) -> &[::std::string::String] {
        self.launch_template_ids.as_deref().unwrap_or_default()
    }
    /// <p>One or more launch template names.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.launch_template_names.is_none()`.
    pub fn launch_template_names(&self) -> &[::std::string::String] {
        self.launch_template_names.as_deref().unwrap_or_default()
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The time the launch template was created.</p></li>
    /// <li>
    /// <p><code>launch-template-name</code> - The name of the launch template.</p></li>
    /// <li>
    /// <p><code>tag</code>:<key>
    /// - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key
    /// <code>Owner</code> and the value
    /// <code>TeamA</code>, specify
    /// <code>tag:Owner</code> for the filter name and
    /// <code>TeamA</code> for the filter value.
    /// </key></p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The token to request the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 1 and 200.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl DescribeLaunchTemplatesInput {
    /// Creates a new builder-style object to manufacture [`DescribeLaunchTemplatesInput`](crate::operation::describe_launch_templates::DescribeLaunchTemplatesInput).
    pub fn builder() -> crate::operation::describe_launch_templates::builders::DescribeLaunchTemplatesInputBuilder {
        crate::operation::describe_launch_templates::builders::DescribeLaunchTemplatesInputBuilder::default()
    }
}

/// A builder for [`DescribeLaunchTemplatesInput`](crate::operation::describe_launch_templates::DescribeLaunchTemplatesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLaunchTemplatesInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) launch_template_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) launch_template_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl DescribeLaunchTemplatesInputBuilder {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Appends an item to `launch_template_ids`.
    ///
    /// To override the contents of this collection use [`set_launch_template_ids`](Self::set_launch_template_ids).
    ///
    /// <p>One or more launch template IDs.</p>
    pub fn launch_template_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.launch_template_ids.unwrap_or_default();
        v.push(input.into());
        self.launch_template_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more launch template IDs.</p>
    pub fn set_launch_template_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.launch_template_ids = input;
        self
    }
    /// <p>One or more launch template IDs.</p>
    pub fn get_launch_template_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.launch_template_ids
    }
    /// Appends an item to `launch_template_names`.
    ///
    /// To override the contents of this collection use [`set_launch_template_names`](Self::set_launch_template_names).
    ///
    /// <p>One or more launch template names.</p>
    pub fn launch_template_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.launch_template_names.unwrap_or_default();
        v.push(input.into());
        self.launch_template_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more launch template names.</p>
    pub fn set_launch_template_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.launch_template_names = input;
        self
    }
    /// <p>One or more launch template names.</p>
    pub fn get_launch_template_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.launch_template_names
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The time the launch template was created.</p></li>
    /// <li>
    /// <p><code>launch-template-name</code> - The name of the launch template.</p></li>
    /// <li>
    /// <p><code>tag</code>:<key>
    /// - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key
    /// <code>Owner</code> and the value
    /// <code>TeamA</code>, specify
    /// <code>tag:Owner</code> for the filter name and
    /// <code>TeamA</code> for the filter value.
    /// </key></p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The time the launch template was created.</p></li>
    /// <li>
    /// <p><code>launch-template-name</code> - The name of the launch template.</p></li>
    /// <li>
    /// <p><code>tag</code>:<key>
    /// - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key
    /// <code>Owner</code> and the value
    /// <code>TeamA</code>, specify
    /// <code>tag:Owner</code> for the filter name and
    /// <code>TeamA</code> for the filter value.
    /// </key></p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The time the launch template was created.</p></li>
    /// <li>
    /// <p><code>launch-template-name</code> - The name of the launch template.</p></li>
    /// <li>
    /// <p><code>tag</code>:<key>
    /// - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key
    /// <code>Owner</code> and the value
    /// <code>TeamA</code>, specify
    /// <code>tag:Owner</code> for the filter name and
    /// <code>TeamA</code> for the filter value.
    /// </key></p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The token to request the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to request the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to request the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 1 and 200.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 1 and 200.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 1 and 200.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`DescribeLaunchTemplatesInput`](crate::operation::describe_launch_templates::DescribeLaunchTemplatesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_launch_templates::DescribeLaunchTemplatesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_launch_templates::DescribeLaunchTemplatesInput {
            dry_run: self.dry_run,
            launch_template_ids: self.launch_template_ids,
            launch_template_names: self.launch_template_names,
            filters: self.filters,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
