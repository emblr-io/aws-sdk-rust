// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListInferenceProfilesInput {
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Filters for inference profiles that match the type you specify.</p>
    /// <ul>
    /// <li>
    /// <p><code>SYSTEM_DEFINED</code> – The inference profile is defined by Amazon Bedrock. You can route inference requests across regions with these inference profiles.</p></li>
    /// <li>
    /// <p><code>APPLICATION</code> – The inference profile was created by a user. This type of inference profile can track metrics and costs when invoking the model in it. The inference profile may route requests to one or multiple regions.</p></li>
    /// </ul>
    pub type_equals: ::std::option::Option<crate::types::InferenceProfileType>,
}
impl ListInferenceProfilesInput {
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Filters for inference profiles that match the type you specify.</p>
    /// <ul>
    /// <li>
    /// <p><code>SYSTEM_DEFINED</code> – The inference profile is defined by Amazon Bedrock. You can route inference requests across regions with these inference profiles.</p></li>
    /// <li>
    /// <p><code>APPLICATION</code> – The inference profile was created by a user. This type of inference profile can track metrics and costs when invoking the model in it. The inference profile may route requests to one or multiple regions.</p></li>
    /// </ul>
    pub fn type_equals(&self) -> ::std::option::Option<&crate::types::InferenceProfileType> {
        self.type_equals.as_ref()
    }
}
impl ListInferenceProfilesInput {
    /// Creates a new builder-style object to manufacture [`ListInferenceProfilesInput`](crate::operation::list_inference_profiles::ListInferenceProfilesInput).
    pub fn builder() -> crate::operation::list_inference_profiles::builders::ListInferenceProfilesInputBuilder {
        crate::operation::list_inference_profiles::builders::ListInferenceProfilesInputBuilder::default()
    }
}

/// A builder for [`ListInferenceProfilesInput`](crate::operation::list_inference_profiles::ListInferenceProfilesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListInferenceProfilesInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) type_equals: ::std::option::Option<crate::types::InferenceProfileType>,
}
impl ListInferenceProfilesInputBuilder {
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Filters for inference profiles that match the type you specify.</p>
    /// <ul>
    /// <li>
    /// <p><code>SYSTEM_DEFINED</code> – The inference profile is defined by Amazon Bedrock. You can route inference requests across regions with these inference profiles.</p></li>
    /// <li>
    /// <p><code>APPLICATION</code> – The inference profile was created by a user. This type of inference profile can track metrics and costs when invoking the model in it. The inference profile may route requests to one or multiple regions.</p></li>
    /// </ul>
    pub fn type_equals(mut self, input: crate::types::InferenceProfileType) -> Self {
        self.type_equals = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters for inference profiles that match the type you specify.</p>
    /// <ul>
    /// <li>
    /// <p><code>SYSTEM_DEFINED</code> – The inference profile is defined by Amazon Bedrock. You can route inference requests across regions with these inference profiles.</p></li>
    /// <li>
    /// <p><code>APPLICATION</code> – The inference profile was created by a user. This type of inference profile can track metrics and costs when invoking the model in it. The inference profile may route requests to one or multiple regions.</p></li>
    /// </ul>
    pub fn set_type_equals(mut self, input: ::std::option::Option<crate::types::InferenceProfileType>) -> Self {
        self.type_equals = input;
        self
    }
    /// <p>Filters for inference profiles that match the type you specify.</p>
    /// <ul>
    /// <li>
    /// <p><code>SYSTEM_DEFINED</code> – The inference profile is defined by Amazon Bedrock. You can route inference requests across regions with these inference profiles.</p></li>
    /// <li>
    /// <p><code>APPLICATION</code> – The inference profile was created by a user. This type of inference profile can track metrics and costs when invoking the model in it. The inference profile may route requests to one or multiple regions.</p></li>
    /// </ul>
    pub fn get_type_equals(&self) -> &::std::option::Option<crate::types::InferenceProfileType> {
        &self.type_equals
    }
    /// Consumes the builder and constructs a [`ListInferenceProfilesInput`](crate::operation::list_inference_profiles::ListInferenceProfilesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_inference_profiles::ListInferenceProfilesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_inference_profiles::ListInferenceProfilesInput {
            max_results: self.max_results,
            next_token: self.next_token,
            type_equals: self.type_equals,
        })
    }
}
