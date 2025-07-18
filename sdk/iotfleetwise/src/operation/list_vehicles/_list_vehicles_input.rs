// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListVehiclesInput {
    /// <p>The Amazon Resource Name (ARN) of a vehicle model (model manifest). You can use this optional parameter to list only the vehicles created from a certain vehicle model.</p>
    pub model_manifest_arn: ::std::option::Option<::std::string::String>,
    /// <p>The fully qualified names of the attributes. You can use this optional parameter to list the vehicles containing all the attributes in the request. For example, <code>attributeNames</code> could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>" and the corresponding <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" . In this case, the API will filter vehicles with an attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filters to return the subset of vehicles that match the attributes filter condition.</p>
    pub attribute_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Static information about a vehicle attribute value in string format. You can use this optional parameter in conjunction with <code>attributeNames</code> to list the vehicles containing all the <code>attributeValues</code> corresponding to the <code>attributeNames</code> filter. For example, <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" and the corresponding <code>attributeNames</code> filter could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>". In this case, the API will filter vehicles with attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filter to return the subset of vehicles that match the attributes filter condition.</p>
    pub attribute_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A pagination token for the next set of results.</p>
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next set of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return, between 1 and 100, inclusive.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>When you set the <code>listResponseScope</code> parameter to <code>METADATA_ONLY</code>, the list response includes: vehicle name, Amazon Resource Name (ARN), creation time, and last modification time.</p>
    pub list_response_scope: ::std::option::Option<crate::types::ListResponseScope>,
}
impl ListVehiclesInput {
    /// <p>The Amazon Resource Name (ARN) of a vehicle model (model manifest). You can use this optional parameter to list only the vehicles created from a certain vehicle model.</p>
    pub fn model_manifest_arn(&self) -> ::std::option::Option<&str> {
        self.model_manifest_arn.as_deref()
    }
    /// <p>The fully qualified names of the attributes. You can use this optional parameter to list the vehicles containing all the attributes in the request. For example, <code>attributeNames</code> could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>" and the corresponding <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" . In this case, the API will filter vehicles with an attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filters to return the subset of vehicles that match the attributes filter condition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attribute_names.is_none()`.
    pub fn attribute_names(&self) -> &[::std::string::String] {
        self.attribute_names.as_deref().unwrap_or_default()
    }
    /// <p>Static information about a vehicle attribute value in string format. You can use this optional parameter in conjunction with <code>attributeNames</code> to list the vehicles containing all the <code>attributeValues</code> corresponding to the <code>attributeNames</code> filter. For example, <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" and the corresponding <code>attributeNames</code> filter could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>". In this case, the API will filter vehicles with attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filter to return the subset of vehicles that match the attributes filter condition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attribute_values.is_none()`.
    pub fn attribute_values(&self) -> &[::std::string::String] {
        self.attribute_values.as_deref().unwrap_or_default()
    }
    /// <p>A pagination token for the next set of results.</p>
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next set of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to return, between 1 and 100, inclusive.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>When you set the <code>listResponseScope</code> parameter to <code>METADATA_ONLY</code>, the list response includes: vehicle name, Amazon Resource Name (ARN), creation time, and last modification time.</p>
    pub fn list_response_scope(&self) -> ::std::option::Option<&crate::types::ListResponseScope> {
        self.list_response_scope.as_ref()
    }
}
impl ListVehiclesInput {
    /// Creates a new builder-style object to manufacture [`ListVehiclesInput`](crate::operation::list_vehicles::ListVehiclesInput).
    pub fn builder() -> crate::operation::list_vehicles::builders::ListVehiclesInputBuilder {
        crate::operation::list_vehicles::builders::ListVehiclesInputBuilder::default()
    }
}

/// A builder for [`ListVehiclesInput`](crate::operation::list_vehicles::ListVehiclesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListVehiclesInputBuilder {
    pub(crate) model_manifest_arn: ::std::option::Option<::std::string::String>,
    pub(crate) attribute_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) attribute_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) list_response_scope: ::std::option::Option<crate::types::ListResponseScope>,
}
impl ListVehiclesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of a vehicle model (model manifest). You can use this optional parameter to list only the vehicles created from a certain vehicle model.</p>
    pub fn model_manifest_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_manifest_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a vehicle model (model manifest). You can use this optional parameter to list only the vehicles created from a certain vehicle model.</p>
    pub fn set_model_manifest_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_manifest_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a vehicle model (model manifest). You can use this optional parameter to list only the vehicles created from a certain vehicle model.</p>
    pub fn get_model_manifest_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_manifest_arn
    }
    /// Appends an item to `attribute_names`.
    ///
    /// To override the contents of this collection use [`set_attribute_names`](Self::set_attribute_names).
    ///
    /// <p>The fully qualified names of the attributes. You can use this optional parameter to list the vehicles containing all the attributes in the request. For example, <code>attributeNames</code> could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>" and the corresponding <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" . In this case, the API will filter vehicles with an attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filters to return the subset of vehicles that match the attributes filter condition.</p>
    pub fn attribute_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.attribute_names.unwrap_or_default();
        v.push(input.into());
        self.attribute_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The fully qualified names of the attributes. You can use this optional parameter to list the vehicles containing all the attributes in the request. For example, <code>attributeNames</code> could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>" and the corresponding <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" . In this case, the API will filter vehicles with an attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filters to return the subset of vehicles that match the attributes filter condition.</p>
    pub fn set_attribute_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.attribute_names = input;
        self
    }
    /// <p>The fully qualified names of the attributes. You can use this optional parameter to list the vehicles containing all the attributes in the request. For example, <code>attributeNames</code> could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>" and the corresponding <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" . In this case, the API will filter vehicles with an attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filters to return the subset of vehicles that match the attributes filter condition.</p>
    pub fn get_attribute_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.attribute_names
    }
    /// Appends an item to `attribute_values`.
    ///
    /// To override the contents of this collection use [`set_attribute_values`](Self::set_attribute_values).
    ///
    /// <p>Static information about a vehicle attribute value in string format. You can use this optional parameter in conjunction with <code>attributeNames</code> to list the vehicles containing all the <code>attributeValues</code> corresponding to the <code>attributeNames</code> filter. For example, <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" and the corresponding <code>attributeNames</code> filter could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>". In this case, the API will filter vehicles with attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filter to return the subset of vehicles that match the attributes filter condition.</p>
    pub fn attribute_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.attribute_values.unwrap_or_default();
        v.push(input.into());
        self.attribute_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Static information about a vehicle attribute value in string format. You can use this optional parameter in conjunction with <code>attributeNames</code> to list the vehicles containing all the <code>attributeValues</code> corresponding to the <code>attributeNames</code> filter. For example, <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" and the corresponding <code>attributeNames</code> filter could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>". In this case, the API will filter vehicles with attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filter to return the subset of vehicles that match the attributes filter condition.</p>
    pub fn set_attribute_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.attribute_values = input;
        self
    }
    /// <p>Static information about a vehicle attribute value in string format. You can use this optional parameter in conjunction with <code>attributeNames</code> to list the vehicles containing all the <code>attributeValues</code> corresponding to the <code>attributeNames</code> filter. For example, <code>attributeValues</code> could be "<code>1.3 L R2, Blue</code>" and the corresponding <code>attributeNames</code> filter could be "<code>Vehicle.Body.Engine.Type, Vehicle.Color</code>". In this case, the API will filter vehicles with attribute name <code>Vehicle.Body.Engine.Type</code> that contains a value of <code>1.3 L R2</code> AND an attribute name <code>Vehicle.Color</code> that contains a value of "<code>Blue</code>". A request must contain unique values for the <code>attributeNames</code> filter and the matching number of <code>attributeValues</code> filter to return the subset of vehicles that match the attributes filter condition.</p>
    pub fn get_attribute_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.attribute_values
    }
    /// <p>A pagination token for the next set of results.</p>
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next set of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token for the next set of results.</p>
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next set of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token for the next set of results.</p>
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next set of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to return, between 1 and 100, inclusive.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return, between 1 and 100, inclusive.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return, between 1 and 100, inclusive.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>When you set the <code>listResponseScope</code> parameter to <code>METADATA_ONLY</code>, the list response includes: vehicle name, Amazon Resource Name (ARN), creation time, and last modification time.</p>
    pub fn list_response_scope(mut self, input: crate::types::ListResponseScope) -> Self {
        self.list_response_scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>When you set the <code>listResponseScope</code> parameter to <code>METADATA_ONLY</code>, the list response includes: vehicle name, Amazon Resource Name (ARN), creation time, and last modification time.</p>
    pub fn set_list_response_scope(mut self, input: ::std::option::Option<crate::types::ListResponseScope>) -> Self {
        self.list_response_scope = input;
        self
    }
    /// <p>When you set the <code>listResponseScope</code> parameter to <code>METADATA_ONLY</code>, the list response includes: vehicle name, Amazon Resource Name (ARN), creation time, and last modification time.</p>
    pub fn get_list_response_scope(&self) -> &::std::option::Option<crate::types::ListResponseScope> {
        &self.list_response_scope
    }
    /// Consumes the builder and constructs a [`ListVehiclesInput`](crate::operation::list_vehicles::ListVehiclesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_vehicles::ListVehiclesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_vehicles::ListVehiclesInput {
            model_manifest_arn: self.model_manifest_arn,
            attribute_names: self.attribute_names,
            attribute_values: self.attribute_values,
            next_token: self.next_token,
            max_results: self.max_results,
            list_response_scope: self.list_response_scope,
        })
    }
}
