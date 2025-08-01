// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFlowOperationsInput {
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    pub firewall_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Availability Zone where the firewall is located. For example, <code>us-east-2a</code>.</p>
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of a VPC endpoint association.</p>
    pub vpc_endpoint_association_arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the primary endpoint associated with a firewall.</p>
    pub vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>An optional string that defines whether any or all operation types are returned.</p>
    pub flow_operation_type: ::std::option::Option<crate::types::FlowOperationType>,
    /// <p>When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of objects that you want Network Firewall to return for this request. If more objects are available, in the response, Network Firewall provides a <code>NextToken</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListFlowOperationsInput {
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    pub fn firewall_arn(&self) -> ::std::option::Option<&str> {
        self.firewall_arn.as_deref()
    }
    /// <p>The ID of the Availability Zone where the firewall is located. For example, <code>us-east-2a</code>.</p>
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of a VPC endpoint association.</p>
    pub fn vpc_endpoint_association_arn(&self) -> ::std::option::Option<&str> {
        self.vpc_endpoint_association_arn.as_deref()
    }
    /// <p>A unique identifier for the primary endpoint associated with a firewall.</p>
    pub fn vpc_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.vpc_endpoint_id.as_deref()
    }
    /// <p>An optional string that defines whether any or all operation types are returned.</p>
    pub fn flow_operation_type(&self) -> ::std::option::Option<&crate::types::FlowOperationType> {
        self.flow_operation_type.as_ref()
    }
    /// <p>When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of objects that you want Network Firewall to return for this request. If more objects are available, in the response, Network Firewall provides a <code>NextToken</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListFlowOperationsInput {
    /// Creates a new builder-style object to manufacture [`ListFlowOperationsInput`](crate::operation::list_flow_operations::ListFlowOperationsInput).
    pub fn builder() -> crate::operation::list_flow_operations::builders::ListFlowOperationsInputBuilder {
        crate::operation::list_flow_operations::builders::ListFlowOperationsInputBuilder::default()
    }
}

/// A builder for [`ListFlowOperationsInput`](crate::operation::list_flow_operations::ListFlowOperationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFlowOperationsInputBuilder {
    pub(crate) firewall_arn: ::std::option::Option<::std::string::String>,
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_endpoint_association_arn: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) flow_operation_type: ::std::option::Option<crate::types::FlowOperationType>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListFlowOperationsInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    /// This field is required.
    pub fn firewall_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.firewall_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    pub fn set_firewall_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.firewall_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    pub fn get_firewall_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.firewall_arn
    }
    /// <p>The ID of the Availability Zone where the firewall is located. For example, <code>us-east-2a</code>.</p>
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Availability Zone where the firewall is located. For example, <code>us-east-2a</code>.</p>
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The ID of the Availability Zone where the firewall is located. For example, <code>us-east-2a</code>.</p>
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>The Amazon Resource Name (ARN) of a VPC endpoint association.</p>
    pub fn vpc_endpoint_association_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_endpoint_association_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a VPC endpoint association.</p>
    pub fn set_vpc_endpoint_association_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_endpoint_association_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a VPC endpoint association.</p>
    pub fn get_vpc_endpoint_association_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_endpoint_association_arn
    }
    /// <p>A unique identifier for the primary endpoint associated with a firewall.</p>
    pub fn vpc_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the primary endpoint associated with a firewall.</p>
    pub fn set_vpc_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_endpoint_id = input;
        self
    }
    /// <p>A unique identifier for the primary endpoint associated with a firewall.</p>
    pub fn get_vpc_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_endpoint_id
    }
    /// <p>An optional string that defines whether any or all operation types are returned.</p>
    pub fn flow_operation_type(mut self, input: crate::types::FlowOperationType) -> Self {
        self.flow_operation_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>An optional string that defines whether any or all operation types are returned.</p>
    pub fn set_flow_operation_type(mut self, input: ::std::option::Option<crate::types::FlowOperationType>) -> Self {
        self.flow_operation_type = input;
        self
    }
    /// <p>An optional string that defines whether any or all operation types are returned.</p>
    pub fn get_flow_operation_type(&self) -> &::std::option::Option<crate::types::FlowOperationType> {
        &self.flow_operation_type
    }
    /// <p>When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>When you request a list of objects with a <code>MaxResults</code> setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a <code>NextToken</code> value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of objects that you want Network Firewall to return for this request. If more objects are available, in the response, Network Firewall provides a <code>NextToken</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of objects that you want Network Firewall to return for this request. If more objects are available, in the response, Network Firewall provides a <code>NextToken</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of objects that you want Network Firewall to return for this request. If more objects are available, in the response, Network Firewall provides a <code>NextToken</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListFlowOperationsInput`](crate::operation::list_flow_operations::ListFlowOperationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_flow_operations::ListFlowOperationsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_flow_operations::ListFlowOperationsInput {
            firewall_arn: self.firewall_arn,
            availability_zone: self.availability_zone,
            vpc_endpoint_association_arn: self.vpc_endpoint_association_arn,
            vpc_endpoint_id: self.vpc_endpoint_id,
            flow_operation_type: self.flow_operation_type,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
