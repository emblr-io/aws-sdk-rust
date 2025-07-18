// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchAgreementsInput {
    /// <p>The catalog in which the agreement was created.</p>
    pub catalog: ::std::option::Option<::std::string::String>,
    /// <p>The filter name and value pair used to return a specific list of results.</p>
    /// <p>The following filters are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceIdentifier</code> – The unique identifier of the resource.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> – Type of the resource, which is the product (<code>AmiProduct</code>, <code>ContainerProduct</code>, or <code>SaaSProduct</code>).</p></li>
    /// <li>
    /// <p><code>PartyType</code> – The party type (either <code>Acceptor</code> or <code>Proposer</code>) of the caller. For agreements where the caller is the proposer, use the <code>Proposer</code> filter. For agreements where the caller is the acceptor, use the <code>Acceptor</code> filter.</p></li>
    /// <li>
    /// <p><code>AcceptorAccountId</code> – The AWS account ID of the party accepting the agreement terms.</p></li>
    /// <li>
    /// <p><code>OfferId</code> – The unique identifier of the offer in which the terms are registered in the agreement token.</p></li>
    /// <li>
    /// <p><code>Status</code> – The current status of the agreement. Values include <code>ACTIVE</code>, <code>ARCHIVED</code>, <code>CANCELLED</code>, <code>EXPIRED</code>, <code>RENEWED</code>, <code>REPLACED</code>, and <code>TERMINATED</code>.</p></li>
    /// <li>
    /// <p><code>BeforeEndTime</code> – A date used to filter agreements with a date before the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AfterEndTime</code> – A date used to filter agreements with a date after the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AgreementType</code> – The type of agreement. Values include <code>PurchaseAgreement</code> or <code>VendorInsightsAgreement</code>.</p></li>
    /// </ul>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>An object that contains the <code>SortBy</code> and <code>SortOrder</code> attributes.</p>
    pub sort: ::std::option::Option<crate::types::Sort>,
    /// <p>The maximum number of agreements to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A token to specify where to start pagination.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl SearchAgreementsInput {
    /// <p>The catalog in which the agreement was created.</p>
    pub fn catalog(&self) -> ::std::option::Option<&str> {
        self.catalog.as_deref()
    }
    /// <p>The filter name and value pair used to return a specific list of results.</p>
    /// <p>The following filters are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceIdentifier</code> – The unique identifier of the resource.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> – Type of the resource, which is the product (<code>AmiProduct</code>, <code>ContainerProduct</code>, or <code>SaaSProduct</code>).</p></li>
    /// <li>
    /// <p><code>PartyType</code> – The party type (either <code>Acceptor</code> or <code>Proposer</code>) of the caller. For agreements where the caller is the proposer, use the <code>Proposer</code> filter. For agreements where the caller is the acceptor, use the <code>Acceptor</code> filter.</p></li>
    /// <li>
    /// <p><code>AcceptorAccountId</code> – The AWS account ID of the party accepting the agreement terms.</p></li>
    /// <li>
    /// <p><code>OfferId</code> – The unique identifier of the offer in which the terms are registered in the agreement token.</p></li>
    /// <li>
    /// <p><code>Status</code> – The current status of the agreement. Values include <code>ACTIVE</code>, <code>ARCHIVED</code>, <code>CANCELLED</code>, <code>EXPIRED</code>, <code>RENEWED</code>, <code>REPLACED</code>, and <code>TERMINATED</code>.</p></li>
    /// <li>
    /// <p><code>BeforeEndTime</code> – A date used to filter agreements with a date before the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AfterEndTime</code> – A date used to filter agreements with a date after the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AgreementType</code> – The type of agreement. Values include <code>PurchaseAgreement</code> or <code>VendorInsightsAgreement</code>.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>An object that contains the <code>SortBy</code> and <code>SortOrder</code> attributes.</p>
    pub fn sort(&self) -> ::std::option::Option<&crate::types::Sort> {
        self.sort.as_ref()
    }
    /// <p>The maximum number of agreements to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A token to specify where to start pagination.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl SearchAgreementsInput {
    /// Creates a new builder-style object to manufacture [`SearchAgreementsInput`](crate::operation::search_agreements::SearchAgreementsInput).
    pub fn builder() -> crate::operation::search_agreements::builders::SearchAgreementsInputBuilder {
        crate::operation::search_agreements::builders::SearchAgreementsInputBuilder::default()
    }
}

/// A builder for [`SearchAgreementsInput`](crate::operation::search_agreements::SearchAgreementsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchAgreementsInputBuilder {
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) sort: ::std::option::Option<crate::types::Sort>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl SearchAgreementsInputBuilder {
    /// <p>The catalog in which the agreement was created.</p>
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The catalog in which the agreement was created.</p>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>The catalog in which the agreement was created.</p>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>The filter name and value pair used to return a specific list of results.</p>
    /// <p>The following filters are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceIdentifier</code> – The unique identifier of the resource.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> – Type of the resource, which is the product (<code>AmiProduct</code>, <code>ContainerProduct</code>, or <code>SaaSProduct</code>).</p></li>
    /// <li>
    /// <p><code>PartyType</code> – The party type (either <code>Acceptor</code> or <code>Proposer</code>) of the caller. For agreements where the caller is the proposer, use the <code>Proposer</code> filter. For agreements where the caller is the acceptor, use the <code>Acceptor</code> filter.</p></li>
    /// <li>
    /// <p><code>AcceptorAccountId</code> – The AWS account ID of the party accepting the agreement terms.</p></li>
    /// <li>
    /// <p><code>OfferId</code> – The unique identifier of the offer in which the terms are registered in the agreement token.</p></li>
    /// <li>
    /// <p><code>Status</code> – The current status of the agreement. Values include <code>ACTIVE</code>, <code>ARCHIVED</code>, <code>CANCELLED</code>, <code>EXPIRED</code>, <code>RENEWED</code>, <code>REPLACED</code>, and <code>TERMINATED</code>.</p></li>
    /// <li>
    /// <p><code>BeforeEndTime</code> – A date used to filter agreements with a date before the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AfterEndTime</code> – A date used to filter agreements with a date after the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AgreementType</code> – The type of agreement. Values include <code>PurchaseAgreement</code> or <code>VendorInsightsAgreement</code>.</p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The filter name and value pair used to return a specific list of results.</p>
    /// <p>The following filters are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceIdentifier</code> – The unique identifier of the resource.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> – Type of the resource, which is the product (<code>AmiProduct</code>, <code>ContainerProduct</code>, or <code>SaaSProduct</code>).</p></li>
    /// <li>
    /// <p><code>PartyType</code> – The party type (either <code>Acceptor</code> or <code>Proposer</code>) of the caller. For agreements where the caller is the proposer, use the <code>Proposer</code> filter. For agreements where the caller is the acceptor, use the <code>Acceptor</code> filter.</p></li>
    /// <li>
    /// <p><code>AcceptorAccountId</code> – The AWS account ID of the party accepting the agreement terms.</p></li>
    /// <li>
    /// <p><code>OfferId</code> – The unique identifier of the offer in which the terms are registered in the agreement token.</p></li>
    /// <li>
    /// <p><code>Status</code> – The current status of the agreement. Values include <code>ACTIVE</code>, <code>ARCHIVED</code>, <code>CANCELLED</code>, <code>EXPIRED</code>, <code>RENEWED</code>, <code>REPLACED</code>, and <code>TERMINATED</code>.</p></li>
    /// <li>
    /// <p><code>BeforeEndTime</code> – A date used to filter agreements with a date before the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AfterEndTime</code> – A date used to filter agreements with a date after the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AgreementType</code> – The type of agreement. Values include <code>PurchaseAgreement</code> or <code>VendorInsightsAgreement</code>.</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>The filter name and value pair used to return a specific list of results.</p>
    /// <p>The following filters are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceIdentifier</code> – The unique identifier of the resource.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> – Type of the resource, which is the product (<code>AmiProduct</code>, <code>ContainerProduct</code>, or <code>SaaSProduct</code>).</p></li>
    /// <li>
    /// <p><code>PartyType</code> – The party type (either <code>Acceptor</code> or <code>Proposer</code>) of the caller. For agreements where the caller is the proposer, use the <code>Proposer</code> filter. For agreements where the caller is the acceptor, use the <code>Acceptor</code> filter.</p></li>
    /// <li>
    /// <p><code>AcceptorAccountId</code> – The AWS account ID of the party accepting the agreement terms.</p></li>
    /// <li>
    /// <p><code>OfferId</code> – The unique identifier of the offer in which the terms are registered in the agreement token.</p></li>
    /// <li>
    /// <p><code>Status</code> – The current status of the agreement. Values include <code>ACTIVE</code>, <code>ARCHIVED</code>, <code>CANCELLED</code>, <code>EXPIRED</code>, <code>RENEWED</code>, <code>REPLACED</code>, and <code>TERMINATED</code>.</p></li>
    /// <li>
    /// <p><code>BeforeEndTime</code> – A date used to filter agreements with a date before the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AfterEndTime</code> – A date used to filter agreements with a date after the <code>endTime</code> of an agreement.</p></li>
    /// <li>
    /// <p><code>AgreementType</code> – The type of agreement. Values include <code>PurchaseAgreement</code> or <code>VendorInsightsAgreement</code>.</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>An object that contains the <code>SortBy</code> and <code>SortOrder</code> attributes.</p>
    pub fn sort(mut self, input: crate::types::Sort) -> Self {
        self.sort = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains the <code>SortBy</code> and <code>SortOrder</code> attributes.</p>
    pub fn set_sort(mut self, input: ::std::option::Option<crate::types::Sort>) -> Self {
        self.sort = input;
        self
    }
    /// <p>An object that contains the <code>SortBy</code> and <code>SortOrder</code> attributes.</p>
    pub fn get_sort(&self) -> &::std::option::Option<crate::types::Sort> {
        &self.sort
    }
    /// <p>The maximum number of agreements to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of agreements to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of agreements to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A token to specify where to start pagination.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to specify where to start pagination.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to specify where to start pagination.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`SearchAgreementsInput`](crate::operation::search_agreements::SearchAgreementsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::search_agreements::SearchAgreementsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::search_agreements::SearchAgreementsInput {
            catalog: self.catalog,
            filters: self.filters,
            sort: self.sort,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
