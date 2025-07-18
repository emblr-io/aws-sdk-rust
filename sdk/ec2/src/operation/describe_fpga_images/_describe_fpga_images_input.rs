// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFpgaImagesInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The AFI IDs.</p>
    pub fpga_image_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filters the AFI by owner. Specify an Amazon Web Services account ID, <code>self</code> (owner is the sender of the request), or an Amazon Web Services owner alias (valid values are <code>amazon</code> | <code>aws-marketplace</code>).</p>
    pub owners: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The creation time of the AFI.</p></li>
    /// <li>
    /// <p><code>fpga-image-id</code> - The FPGA image identifier (AFI ID).</p></li>
    /// <li>
    /// <p><code>fpga-image-global-id</code> - The global FPGA image identifier (AGFI ID).</p></li>
    /// <li>
    /// <p><code>name</code> - The name of the AFI.</p></li>
    /// <li>
    /// <p><code>owner-id</code> - The Amazon Web Services account ID of the AFI owner.</p></li>
    /// <li>
    /// <p><code>product-code</code> - The product code.</p></li>
    /// <li>
    /// <p><code>shell-version</code> - The version of the Amazon Web Services Shell that was used to create the bitstream.</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the AFI (<code>pending</code> | <code>failed</code> | <code>available</code> | <code>unavailable</code>).</p></li>
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
    /// <li>
    /// <p><code>update-time</code> - The time of the most recent update.</p></li>
    /// </ul>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The token to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in a single call.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl DescribeFpgaImagesInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The AFI IDs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fpga_image_ids.is_none()`.
    pub fn fpga_image_ids(&self) -> &[::std::string::String] {
        self.fpga_image_ids.as_deref().unwrap_or_default()
    }
    /// <p>Filters the AFI by owner. Specify an Amazon Web Services account ID, <code>self</code> (owner is the sender of the request), or an Amazon Web Services owner alias (valid values are <code>amazon</code> | <code>aws-marketplace</code>).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.owners.is_none()`.
    pub fn owners(&self) -> &[::std::string::String] {
        self.owners.as_deref().unwrap_or_default()
    }
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The creation time of the AFI.</p></li>
    /// <li>
    /// <p><code>fpga-image-id</code> - The FPGA image identifier (AFI ID).</p></li>
    /// <li>
    /// <p><code>fpga-image-global-id</code> - The global FPGA image identifier (AGFI ID).</p></li>
    /// <li>
    /// <p><code>name</code> - The name of the AFI.</p></li>
    /// <li>
    /// <p><code>owner-id</code> - The Amazon Web Services account ID of the AFI owner.</p></li>
    /// <li>
    /// <p><code>product-code</code> - The product code.</p></li>
    /// <li>
    /// <p><code>shell-version</code> - The version of the Amazon Web Services Shell that was used to create the bitstream.</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the AFI (<code>pending</code> | <code>failed</code> | <code>available</code> | <code>unavailable</code>).</p></li>
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
    /// <li>
    /// <p><code>update-time</code> - The time of the most recent update.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The token to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl DescribeFpgaImagesInput {
    /// Creates a new builder-style object to manufacture [`DescribeFpgaImagesInput`](crate::operation::describe_fpga_images::DescribeFpgaImagesInput).
    pub fn builder() -> crate::operation::describe_fpga_images::builders::DescribeFpgaImagesInputBuilder {
        crate::operation::describe_fpga_images::builders::DescribeFpgaImagesInputBuilder::default()
    }
}

/// A builder for [`DescribeFpgaImagesInput`](crate::operation::describe_fpga_images::DescribeFpgaImagesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFpgaImagesInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) fpga_image_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) owners: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl DescribeFpgaImagesInputBuilder {
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
    /// Appends an item to `fpga_image_ids`.
    ///
    /// To override the contents of this collection use [`set_fpga_image_ids`](Self::set_fpga_image_ids).
    ///
    /// <p>The AFI IDs.</p>
    pub fn fpga_image_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.fpga_image_ids.unwrap_or_default();
        v.push(input.into());
        self.fpga_image_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The AFI IDs.</p>
    pub fn set_fpga_image_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.fpga_image_ids = input;
        self
    }
    /// <p>The AFI IDs.</p>
    pub fn get_fpga_image_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.fpga_image_ids
    }
    /// Appends an item to `owners`.
    ///
    /// To override the contents of this collection use [`set_owners`](Self::set_owners).
    ///
    /// <p>Filters the AFI by owner. Specify an Amazon Web Services account ID, <code>self</code> (owner is the sender of the request), or an Amazon Web Services owner alias (valid values are <code>amazon</code> | <code>aws-marketplace</code>).</p>
    pub fn owners(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.owners.unwrap_or_default();
        v.push(input.into());
        self.owners = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the AFI by owner. Specify an Amazon Web Services account ID, <code>self</code> (owner is the sender of the request), or an Amazon Web Services owner alias (valid values are <code>amazon</code> | <code>aws-marketplace</code>).</p>
    pub fn set_owners(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.owners = input;
        self
    }
    /// <p>Filters the AFI by owner. Specify an Amazon Web Services account ID, <code>self</code> (owner is the sender of the request), or an Amazon Web Services owner alias (valid values are <code>amazon</code> | <code>aws-marketplace</code>).</p>
    pub fn get_owners(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.owners
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The creation time of the AFI.</p></li>
    /// <li>
    /// <p><code>fpga-image-id</code> - The FPGA image identifier (AFI ID).</p></li>
    /// <li>
    /// <p><code>fpga-image-global-id</code> - The global FPGA image identifier (AGFI ID).</p></li>
    /// <li>
    /// <p><code>name</code> - The name of the AFI.</p></li>
    /// <li>
    /// <p><code>owner-id</code> - The Amazon Web Services account ID of the AFI owner.</p></li>
    /// <li>
    /// <p><code>product-code</code> - The product code.</p></li>
    /// <li>
    /// <p><code>shell-version</code> - The version of the Amazon Web Services Shell that was used to create the bitstream.</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the AFI (<code>pending</code> | <code>failed</code> | <code>available</code> | <code>unavailable</code>).</p></li>
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
    /// <li>
    /// <p><code>update-time</code> - The time of the most recent update.</p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The creation time of the AFI.</p></li>
    /// <li>
    /// <p><code>fpga-image-id</code> - The FPGA image identifier (AFI ID).</p></li>
    /// <li>
    /// <p><code>fpga-image-global-id</code> - The global FPGA image identifier (AGFI ID).</p></li>
    /// <li>
    /// <p><code>name</code> - The name of the AFI.</p></li>
    /// <li>
    /// <p><code>owner-id</code> - The Amazon Web Services account ID of the AFI owner.</p></li>
    /// <li>
    /// <p><code>product-code</code> - The product code.</p></li>
    /// <li>
    /// <p><code>shell-version</code> - The version of the Amazon Web Services Shell that was used to create the bitstream.</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the AFI (<code>pending</code> | <code>failed</code> | <code>available</code> | <code>unavailable</code>).</p></li>
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
    /// <li>
    /// <p><code>update-time</code> - The time of the most recent update.</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>create-time</code> - The creation time of the AFI.</p></li>
    /// <li>
    /// <p><code>fpga-image-id</code> - The FPGA image identifier (AFI ID).</p></li>
    /// <li>
    /// <p><code>fpga-image-global-id</code> - The global FPGA image identifier (AGFI ID).</p></li>
    /// <li>
    /// <p><code>name</code> - The name of the AFI.</p></li>
    /// <li>
    /// <p><code>owner-id</code> - The Amazon Web Services account ID of the AFI owner.</p></li>
    /// <li>
    /// <p><code>product-code</code> - The product code.</p></li>
    /// <li>
    /// <p><code>shell-version</code> - The version of the Amazon Web Services Shell that was used to create the bitstream.</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the AFI (<code>pending</code> | <code>failed</code> | <code>available</code> | <code>unavailable</code>).</p></li>
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
    /// <li>
    /// <p><code>update-time</code> - The time of the most recent update.</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The token to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to retrieve the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`DescribeFpgaImagesInput`](crate::operation::describe_fpga_images::DescribeFpgaImagesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_fpga_images::DescribeFpgaImagesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_fpga_images::DescribeFpgaImagesInput {
            dry_run: self.dry_run,
            fpga_image_ids: self.fpga_image_ids,
            owners: self.owners,
            filters: self.filters,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
