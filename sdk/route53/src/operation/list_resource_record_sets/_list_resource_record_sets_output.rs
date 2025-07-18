// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains list information for the resource record set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResourceRecordSetsOutput {
    /// <p>Information about multiple resource record sets.</p>
    pub resource_record_sets: ::std::vec::Vec<crate::types::ResourceRecordSet>,
    /// <p>A flag that indicates whether more resource record sets remain to be listed. If your results were truncated, you can make a follow-up pagination request by using the <code>NextRecordName</code> element.</p>
    pub is_truncated: bool,
    /// <p>If the results were truncated, the name of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub next_record_name: ::std::option::Option<::std::string::String>,
    /// <p>If the results were truncated, the type of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub next_record_type: ::std::option::Option<crate::types::RrType>,
    /// <p><i>Resource record sets that have a routing policy other than simple:</i> If results were truncated for a given DNS name and type, the value of <code>SetIdentifier</code> for the next resource record set that has the current DNS name and type.</p>
    /// <p>For information about routing policies, see <a href="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html">Choosing a Routing Policy</a> in the <i>Amazon Route 53 Developer Guide</i>.</p>
    pub next_record_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of records you requested.</p>
    pub max_items: i32,
    _request_id: Option<String>,
}
impl ListResourceRecordSetsOutput {
    /// <p>Information about multiple resource record sets.</p>
    pub fn resource_record_sets(&self) -> &[crate::types::ResourceRecordSet] {
        use std::ops::Deref;
        self.resource_record_sets.deref()
    }
    /// <p>A flag that indicates whether more resource record sets remain to be listed. If your results were truncated, you can make a follow-up pagination request by using the <code>NextRecordName</code> element.</p>
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }
    /// <p>If the results were truncated, the name of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub fn next_record_name(&self) -> ::std::option::Option<&str> {
        self.next_record_name.as_deref()
    }
    /// <p>If the results were truncated, the type of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub fn next_record_type(&self) -> ::std::option::Option<&crate::types::RrType> {
        self.next_record_type.as_ref()
    }
    /// <p><i>Resource record sets that have a routing policy other than simple:</i> If results were truncated for a given DNS name and type, the value of <code>SetIdentifier</code> for the next resource record set that has the current DNS name and type.</p>
    /// <p>For information about routing policies, see <a href="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html">Choosing a Routing Policy</a> in the <i>Amazon Route 53 Developer Guide</i>.</p>
    pub fn next_record_identifier(&self) -> ::std::option::Option<&str> {
        self.next_record_identifier.as_deref()
    }
    /// <p>The maximum number of records you requested.</p>
    pub fn max_items(&self) -> i32 {
        self.max_items
    }
}
impl ::aws_types::request_id::RequestId for ListResourceRecordSetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListResourceRecordSetsOutput {
    /// Creates a new builder-style object to manufacture [`ListResourceRecordSetsOutput`](crate::operation::list_resource_record_sets::ListResourceRecordSetsOutput).
    pub fn builder() -> crate::operation::list_resource_record_sets::builders::ListResourceRecordSetsOutputBuilder {
        crate::operation::list_resource_record_sets::builders::ListResourceRecordSetsOutputBuilder::default()
    }
}

/// A builder for [`ListResourceRecordSetsOutput`](crate::operation::list_resource_record_sets::ListResourceRecordSetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResourceRecordSetsOutputBuilder {
    pub(crate) resource_record_sets: ::std::option::Option<::std::vec::Vec<crate::types::ResourceRecordSet>>,
    pub(crate) is_truncated: ::std::option::Option<bool>,
    pub(crate) next_record_name: ::std::option::Option<::std::string::String>,
    pub(crate) next_record_type: ::std::option::Option<crate::types::RrType>,
    pub(crate) next_record_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl ListResourceRecordSetsOutputBuilder {
    /// Appends an item to `resource_record_sets`.
    ///
    /// To override the contents of this collection use [`set_resource_record_sets`](Self::set_resource_record_sets).
    ///
    /// <p>Information about multiple resource record sets.</p>
    pub fn resource_record_sets(mut self, input: crate::types::ResourceRecordSet) -> Self {
        let mut v = self.resource_record_sets.unwrap_or_default();
        v.push(input);
        self.resource_record_sets = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about multiple resource record sets.</p>
    pub fn set_resource_record_sets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceRecordSet>>) -> Self {
        self.resource_record_sets = input;
        self
    }
    /// <p>Information about multiple resource record sets.</p>
    pub fn get_resource_record_sets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceRecordSet>> {
        &self.resource_record_sets
    }
    /// <p>A flag that indicates whether more resource record sets remain to be listed. If your results were truncated, you can make a follow-up pagination request by using the <code>NextRecordName</code> element.</p>
    /// This field is required.
    pub fn is_truncated(mut self, input: bool) -> Self {
        self.is_truncated = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag that indicates whether more resource record sets remain to be listed. If your results were truncated, you can make a follow-up pagination request by using the <code>NextRecordName</code> element.</p>
    pub fn set_is_truncated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_truncated = input;
        self
    }
    /// <p>A flag that indicates whether more resource record sets remain to be listed. If your results were truncated, you can make a follow-up pagination request by using the <code>NextRecordName</code> element.</p>
    pub fn get_is_truncated(&self) -> &::std::option::Option<bool> {
        &self.is_truncated
    }
    /// <p>If the results were truncated, the name of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub fn next_record_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_record_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the results were truncated, the name of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub fn set_next_record_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_record_name = input;
        self
    }
    /// <p>If the results were truncated, the name of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub fn get_next_record_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_record_name
    }
    /// <p>If the results were truncated, the type of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub fn next_record_type(mut self, input: crate::types::RrType) -> Self {
        self.next_record_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the results were truncated, the type of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub fn set_next_record_type(mut self, input: ::std::option::Option<crate::types::RrType>) -> Self {
        self.next_record_type = input;
        self
    }
    /// <p>If the results were truncated, the type of the next record in the list.</p>
    /// <p>This element is present only if <code>IsTruncated</code> is true.</p>
    pub fn get_next_record_type(&self) -> &::std::option::Option<crate::types::RrType> {
        &self.next_record_type
    }
    /// <p><i>Resource record sets that have a routing policy other than simple:</i> If results were truncated for a given DNS name and type, the value of <code>SetIdentifier</code> for the next resource record set that has the current DNS name and type.</p>
    /// <p>For information about routing policies, see <a href="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html">Choosing a Routing Policy</a> in the <i>Amazon Route 53 Developer Guide</i>.</p>
    pub fn next_record_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_record_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><i>Resource record sets that have a routing policy other than simple:</i> If results were truncated for a given DNS name and type, the value of <code>SetIdentifier</code> for the next resource record set that has the current DNS name and type.</p>
    /// <p>For information about routing policies, see <a href="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html">Choosing a Routing Policy</a> in the <i>Amazon Route 53 Developer Guide</i>.</p>
    pub fn set_next_record_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_record_identifier = input;
        self
    }
    /// <p><i>Resource record sets that have a routing policy other than simple:</i> If results were truncated for a given DNS name and type, the value of <code>SetIdentifier</code> for the next resource record set that has the current DNS name and type.</p>
    /// <p>For information about routing policies, see <a href="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html">Choosing a Routing Policy</a> in the <i>Amazon Route 53 Developer Guide</i>.</p>
    pub fn get_next_record_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_record_identifier
    }
    /// <p>The maximum number of records you requested.</p>
    /// This field is required.
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of records you requested.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>The maximum number of records you requested.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListResourceRecordSetsOutput`](crate::operation::list_resource_record_sets::ListResourceRecordSetsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`resource_record_sets`](crate::operation::list_resource_record_sets::builders::ListResourceRecordSetsOutputBuilder::resource_record_sets)
    /// - [`max_items`](crate::operation::list_resource_record_sets::builders::ListResourceRecordSetsOutputBuilder::max_items)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_resource_record_sets::ListResourceRecordSetsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_resource_record_sets::ListResourceRecordSetsOutput {
            resource_record_sets: self.resource_record_sets.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_record_sets",
                    "resource_record_sets was not specified but it is required when building ListResourceRecordSetsOutput",
                )
            })?,
            is_truncated: self.is_truncated.unwrap_or_default(),
            next_record_name: self.next_record_name,
            next_record_type: self.next_record_type,
            next_record_identifier: self.next_record_identifier,
            max_items: self.max_items.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_items",
                    "max_items was not specified but it is required when building ListResourceRecordSetsOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
