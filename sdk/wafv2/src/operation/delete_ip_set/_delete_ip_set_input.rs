// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteIpSetInput {
    /// <p>The name of the IP set. You cannot change the name of an <code>IPSet</code> after you create it.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub scope: ::std::option::Option<crate::types::Scope>,
    /// <p>A unique identifier for the set. This ID is returned in the responses to create and list commands. You provide it to operations like update and delete.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A token used for optimistic locking. WAF returns a token to your <code>get</code> and <code>list</code> requests, to mark the state of the entity at the time of the request. To make changes to the entity associated with the token, you provide the token to operations like <code>update</code> and <code>delete</code>. WAF uses the token to ensure that no changes have been made to the entity since you last retrieved it. If a change has been made, the update fails with a <code>WAFOptimisticLockException</code>. If this happens, perform another <code>get</code>, and use the new token returned by that operation.</p>
    pub lock_token: ::std::option::Option<::std::string::String>,
}
impl DeleteIpSetInput {
    /// <p>The name of the IP set. You cannot change the name of an <code>IPSet</code> after you create it.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn scope(&self) -> ::std::option::Option<&crate::types::Scope> {
        self.scope.as_ref()
    }
    /// <p>A unique identifier for the set. This ID is returned in the responses to create and list commands. You provide it to operations like update and delete.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A token used for optimistic locking. WAF returns a token to your <code>get</code> and <code>list</code> requests, to mark the state of the entity at the time of the request. To make changes to the entity associated with the token, you provide the token to operations like <code>update</code> and <code>delete</code>. WAF uses the token to ensure that no changes have been made to the entity since you last retrieved it. If a change has been made, the update fails with a <code>WAFOptimisticLockException</code>. If this happens, perform another <code>get</code>, and use the new token returned by that operation.</p>
    pub fn lock_token(&self) -> ::std::option::Option<&str> {
        self.lock_token.as_deref()
    }
}
impl DeleteIpSetInput {
    /// Creates a new builder-style object to manufacture [`DeleteIpSetInput`](crate::operation::delete_ip_set::DeleteIpSetInput).
    pub fn builder() -> crate::operation::delete_ip_set::builders::DeleteIpSetInputBuilder {
        crate::operation::delete_ip_set::builders::DeleteIpSetInputBuilder::default()
    }
}

/// A builder for [`DeleteIpSetInput`](crate::operation::delete_ip_set::DeleteIpSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteIpSetInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) scope: ::std::option::Option<crate::types::Scope>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) lock_token: ::std::option::Option<::std::string::String>,
}
impl DeleteIpSetInputBuilder {
    /// <p>The name of the IP set. You cannot change the name of an <code>IPSet</code> after you create it.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IP set. You cannot change the name of an <code>IPSet</code> after you create it.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the IP set. You cannot change the name of an <code>IPSet</code> after you create it.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    /// This field is required.
    pub fn scope(mut self, input: crate::types::Scope) -> Self {
        self.scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn set_scope(mut self, input: ::std::option::Option<crate::types::Scope>) -> Self {
        self.scope = input;
        self
    }
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn get_scope(&self) -> &::std::option::Option<crate::types::Scope> {
        &self.scope
    }
    /// <p>A unique identifier for the set. This ID is returned in the responses to create and list commands. You provide it to operations like update and delete.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the set. This ID is returned in the responses to create and list commands. You provide it to operations like update and delete.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>A unique identifier for the set. This ID is returned in the responses to create and list commands. You provide it to operations like update and delete.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A token used for optimistic locking. WAF returns a token to your <code>get</code> and <code>list</code> requests, to mark the state of the entity at the time of the request. To make changes to the entity associated with the token, you provide the token to operations like <code>update</code> and <code>delete</code>. WAF uses the token to ensure that no changes have been made to the entity since you last retrieved it. If a change has been made, the update fails with a <code>WAFOptimisticLockException</code>. If this happens, perform another <code>get</code>, and use the new token returned by that operation.</p>
    /// This field is required.
    pub fn lock_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lock_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token used for optimistic locking. WAF returns a token to your <code>get</code> and <code>list</code> requests, to mark the state of the entity at the time of the request. To make changes to the entity associated with the token, you provide the token to operations like <code>update</code> and <code>delete</code>. WAF uses the token to ensure that no changes have been made to the entity since you last retrieved it. If a change has been made, the update fails with a <code>WAFOptimisticLockException</code>. If this happens, perform another <code>get</code>, and use the new token returned by that operation.</p>
    pub fn set_lock_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lock_token = input;
        self
    }
    /// <p>A token used for optimistic locking. WAF returns a token to your <code>get</code> and <code>list</code> requests, to mark the state of the entity at the time of the request. To make changes to the entity associated with the token, you provide the token to operations like <code>update</code> and <code>delete</code>. WAF uses the token to ensure that no changes have been made to the entity since you last retrieved it. If a change has been made, the update fails with a <code>WAFOptimisticLockException</code>. If this happens, perform another <code>get</code>, and use the new token returned by that operation.</p>
    pub fn get_lock_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.lock_token
    }
    /// Consumes the builder and constructs a [`DeleteIpSetInput`](crate::operation::delete_ip_set::DeleteIpSetInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_ip_set::DeleteIpSetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_ip_set::DeleteIpSetInput {
            name: self.name,
            scope: self.scope,
            id: self.id,
            lock_token: self.lock_token,
        })
    }
}
