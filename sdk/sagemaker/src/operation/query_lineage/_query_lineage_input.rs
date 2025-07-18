// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueryLineageInput {
    /// <p>A list of resource Amazon Resource Name (ARN) that represent the starting point for your lineage query.</p>
    pub start_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Associations between lineage entities have a direction. This parameter determines the direction from the StartArn(s) that the query traverses.</p>
    pub direction: ::std::option::Option<crate::types::Direction>,
    /// <p>Setting this value to <code>True</code> retrieves not only the entities of interest but also the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/lineage-tracking-entities.html">Associations</a> and lineage entities on the path. Set to <code>False</code> to only return lineage entities that match your query.</p>
    pub include_edges: ::std::option::Option<bool>,
    /// <p>A set of filtering parameters that allow you to specify which entities should be returned.</p>
    /// <ul>
    /// <li>
    /// <p>Properties - Key-value pairs to match on the lineage entities' properties.</p></li>
    /// <li>
    /// <p>LineageTypes - A set of lineage entity types to match on. For example: <code>TrialComponent</code>, <code>Artifact</code>, or <code>Context</code>.</p></li>
    /// <li>
    /// <p>CreatedBefore - Filter entities created before this date.</p></li>
    /// <li>
    /// <p>ModifiedBefore - Filter entities modified before this date.</p></li>
    /// <li>
    /// <p>ModifiedAfter - Filter entities modified after this date.</p></li>
    /// </ul>
    pub filters: ::std::option::Option<crate::types::QueryFilters>,
    /// <p>The maximum depth in lineage relationships from the <code>StartArns</code> that are traversed. Depth is a measure of the number of <code>Associations</code> from the <code>StartArn</code> entity to the matched results.</p>
    pub max_depth: ::std::option::Option<i32>,
    /// <p>Limits the number of vertices in the results. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Limits the number of vertices in the request. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl QueryLineageInput {
    /// <p>A list of resource Amazon Resource Name (ARN) that represent the starting point for your lineage query.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.start_arns.is_none()`.
    pub fn start_arns(&self) -> &[::std::string::String] {
        self.start_arns.as_deref().unwrap_or_default()
    }
    /// <p>Associations between lineage entities have a direction. This parameter determines the direction from the StartArn(s) that the query traverses.</p>
    pub fn direction(&self) -> ::std::option::Option<&crate::types::Direction> {
        self.direction.as_ref()
    }
    /// <p>Setting this value to <code>True</code> retrieves not only the entities of interest but also the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/lineage-tracking-entities.html">Associations</a> and lineage entities on the path. Set to <code>False</code> to only return lineage entities that match your query.</p>
    pub fn include_edges(&self) -> ::std::option::Option<bool> {
        self.include_edges
    }
    /// <p>A set of filtering parameters that allow you to specify which entities should be returned.</p>
    /// <ul>
    /// <li>
    /// <p>Properties - Key-value pairs to match on the lineage entities' properties.</p></li>
    /// <li>
    /// <p>LineageTypes - A set of lineage entity types to match on. For example: <code>TrialComponent</code>, <code>Artifact</code>, or <code>Context</code>.</p></li>
    /// <li>
    /// <p>CreatedBefore - Filter entities created before this date.</p></li>
    /// <li>
    /// <p>ModifiedBefore - Filter entities modified before this date.</p></li>
    /// <li>
    /// <p>ModifiedAfter - Filter entities modified after this date.</p></li>
    /// </ul>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::QueryFilters> {
        self.filters.as_ref()
    }
    /// <p>The maximum depth in lineage relationships from the <code>StartArns</code> that are traversed. Depth is a measure of the number of <code>Associations</code> from the <code>StartArn</code> entity to the matched results.</p>
    pub fn max_depth(&self) -> ::std::option::Option<i32> {
        self.max_depth
    }
    /// <p>Limits the number of vertices in the results. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Limits the number of vertices in the request. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl QueryLineageInput {
    /// Creates a new builder-style object to manufacture [`QueryLineageInput`](crate::operation::query_lineage::QueryLineageInput).
    pub fn builder() -> crate::operation::query_lineage::builders::QueryLineageInputBuilder {
        crate::operation::query_lineage::builders::QueryLineageInputBuilder::default()
    }
}

/// A builder for [`QueryLineageInput`](crate::operation::query_lineage::QueryLineageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueryLineageInputBuilder {
    pub(crate) start_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) direction: ::std::option::Option<crate::types::Direction>,
    pub(crate) include_edges: ::std::option::Option<bool>,
    pub(crate) filters: ::std::option::Option<crate::types::QueryFilters>,
    pub(crate) max_depth: ::std::option::Option<i32>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl QueryLineageInputBuilder {
    /// Appends an item to `start_arns`.
    ///
    /// To override the contents of this collection use [`set_start_arns`](Self::set_start_arns).
    ///
    /// <p>A list of resource Amazon Resource Name (ARN) that represent the starting point for your lineage query.</p>
    pub fn start_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.start_arns.unwrap_or_default();
        v.push(input.into());
        self.start_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of resource Amazon Resource Name (ARN) that represent the starting point for your lineage query.</p>
    pub fn set_start_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.start_arns = input;
        self
    }
    /// <p>A list of resource Amazon Resource Name (ARN) that represent the starting point for your lineage query.</p>
    pub fn get_start_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.start_arns
    }
    /// <p>Associations between lineage entities have a direction. This parameter determines the direction from the StartArn(s) that the query traverses.</p>
    pub fn direction(mut self, input: crate::types::Direction) -> Self {
        self.direction = ::std::option::Option::Some(input);
        self
    }
    /// <p>Associations between lineage entities have a direction. This parameter determines the direction from the StartArn(s) that the query traverses.</p>
    pub fn set_direction(mut self, input: ::std::option::Option<crate::types::Direction>) -> Self {
        self.direction = input;
        self
    }
    /// <p>Associations between lineage entities have a direction. This parameter determines the direction from the StartArn(s) that the query traverses.</p>
    pub fn get_direction(&self) -> &::std::option::Option<crate::types::Direction> {
        &self.direction
    }
    /// <p>Setting this value to <code>True</code> retrieves not only the entities of interest but also the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/lineage-tracking-entities.html">Associations</a> and lineage entities on the path. Set to <code>False</code> to only return lineage entities that match your query.</p>
    pub fn include_edges(mut self, input: bool) -> Self {
        self.include_edges = ::std::option::Option::Some(input);
        self
    }
    /// <p>Setting this value to <code>True</code> retrieves not only the entities of interest but also the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/lineage-tracking-entities.html">Associations</a> and lineage entities on the path. Set to <code>False</code> to only return lineage entities that match your query.</p>
    pub fn set_include_edges(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_edges = input;
        self
    }
    /// <p>Setting this value to <code>True</code> retrieves not only the entities of interest but also the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/lineage-tracking-entities.html">Associations</a> and lineage entities on the path. Set to <code>False</code> to only return lineage entities that match your query.</p>
    pub fn get_include_edges(&self) -> &::std::option::Option<bool> {
        &self.include_edges
    }
    /// <p>A set of filtering parameters that allow you to specify which entities should be returned.</p>
    /// <ul>
    /// <li>
    /// <p>Properties - Key-value pairs to match on the lineage entities' properties.</p></li>
    /// <li>
    /// <p>LineageTypes - A set of lineage entity types to match on. For example: <code>TrialComponent</code>, <code>Artifact</code>, or <code>Context</code>.</p></li>
    /// <li>
    /// <p>CreatedBefore - Filter entities created before this date.</p></li>
    /// <li>
    /// <p>ModifiedBefore - Filter entities modified before this date.</p></li>
    /// <li>
    /// <p>ModifiedAfter - Filter entities modified after this date.</p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::QueryFilters) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>A set of filtering parameters that allow you to specify which entities should be returned.</p>
    /// <ul>
    /// <li>
    /// <p>Properties - Key-value pairs to match on the lineage entities' properties.</p></li>
    /// <li>
    /// <p>LineageTypes - A set of lineage entity types to match on. For example: <code>TrialComponent</code>, <code>Artifact</code>, or <code>Context</code>.</p></li>
    /// <li>
    /// <p>CreatedBefore - Filter entities created before this date.</p></li>
    /// <li>
    /// <p>ModifiedBefore - Filter entities modified before this date.</p></li>
    /// <li>
    /// <p>ModifiedAfter - Filter entities modified after this date.</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::QueryFilters>) -> Self {
        self.filters = input;
        self
    }
    /// <p>A set of filtering parameters that allow you to specify which entities should be returned.</p>
    /// <ul>
    /// <li>
    /// <p>Properties - Key-value pairs to match on the lineage entities' properties.</p></li>
    /// <li>
    /// <p>LineageTypes - A set of lineage entity types to match on. For example: <code>TrialComponent</code>, <code>Artifact</code>, or <code>Context</code>.</p></li>
    /// <li>
    /// <p>CreatedBefore - Filter entities created before this date.</p></li>
    /// <li>
    /// <p>ModifiedBefore - Filter entities modified before this date.</p></li>
    /// <li>
    /// <p>ModifiedAfter - Filter entities modified after this date.</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::QueryFilters> {
        &self.filters
    }
    /// <p>The maximum depth in lineage relationships from the <code>StartArns</code> that are traversed. Depth is a measure of the number of <code>Associations</code> from the <code>StartArn</code> entity to the matched results.</p>
    pub fn max_depth(mut self, input: i32) -> Self {
        self.max_depth = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum depth in lineage relationships from the <code>StartArns</code> that are traversed. Depth is a measure of the number of <code>Associations</code> from the <code>StartArn</code> entity to the matched results.</p>
    pub fn set_max_depth(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_depth = input;
        self
    }
    /// <p>The maximum depth in lineage relationships from the <code>StartArns</code> that are traversed. Depth is a measure of the number of <code>Associations</code> from the <code>StartArn</code> entity to the matched results.</p>
    pub fn get_max_depth(&self) -> &::std::option::Option<i32> {
        &self.max_depth
    }
    /// <p>Limits the number of vertices in the results. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Limits the number of vertices in the results. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Limits the number of vertices in the results. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Limits the number of vertices in the request. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Limits the number of vertices in the request. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Limits the number of vertices in the request. Use the <code>NextToken</code> in a response to to retrieve the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`QueryLineageInput`](crate::operation::query_lineage::QueryLineageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::query_lineage::QueryLineageInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::query_lineage::QueryLineageInput {
            start_arns: self.start_arns,
            direction: self.direction,
            include_edges: self.include_edges,
            filters: self.filters,
            max_depth: self.max_depth,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
