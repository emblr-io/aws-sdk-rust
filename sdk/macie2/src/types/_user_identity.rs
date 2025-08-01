// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about the type and other characteristics of an entity that performed an action on an affected resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UserIdentity {
    /// <p>If the action was performed with temporary security credentials that were obtained using the AssumeRole operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub assumed_role: ::std::option::Option<crate::types::AssumedRole>,
    /// <p>If the action was performed using the credentials for another Amazon Web Services account, the details of that account.</p>
    pub aws_account: ::std::option::Option<crate::types::AwsAccount>,
    /// <p>If the action was performed by an Amazon Web Services account that belongs to an Amazon Web Services service, the name of the service.</p>
    pub aws_service: ::std::option::Option<crate::types::AwsService>,
    /// <p>If the action was performed with temporary security credentials that were obtained using the GetFederationToken operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub federated_user: ::std::option::Option<crate::types::FederatedUser>,
    /// <p>If the action was performed using the credentials for an Identity and Access Management (IAM) user, the name and other details about the user.</p>
    pub iam_user: ::std::option::Option<crate::types::IamUser>,
    /// <p>If the action was performed using the credentials for your Amazon Web Services account, the details of your account.</p>
    pub root: ::std::option::Option<crate::types::UserIdentityRoot>,
    /// <p>The type of entity that performed the action.</p>
    pub r#type: ::std::option::Option<crate::types::UserIdentityType>,
}
impl UserIdentity {
    /// <p>If the action was performed with temporary security credentials that were obtained using the AssumeRole operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub fn assumed_role(&self) -> ::std::option::Option<&crate::types::AssumedRole> {
        self.assumed_role.as_ref()
    }
    /// <p>If the action was performed using the credentials for another Amazon Web Services account, the details of that account.</p>
    pub fn aws_account(&self) -> ::std::option::Option<&crate::types::AwsAccount> {
        self.aws_account.as_ref()
    }
    /// <p>If the action was performed by an Amazon Web Services account that belongs to an Amazon Web Services service, the name of the service.</p>
    pub fn aws_service(&self) -> ::std::option::Option<&crate::types::AwsService> {
        self.aws_service.as_ref()
    }
    /// <p>If the action was performed with temporary security credentials that were obtained using the GetFederationToken operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub fn federated_user(&self) -> ::std::option::Option<&crate::types::FederatedUser> {
        self.federated_user.as_ref()
    }
    /// <p>If the action was performed using the credentials for an Identity and Access Management (IAM) user, the name and other details about the user.</p>
    pub fn iam_user(&self) -> ::std::option::Option<&crate::types::IamUser> {
        self.iam_user.as_ref()
    }
    /// <p>If the action was performed using the credentials for your Amazon Web Services account, the details of your account.</p>
    pub fn root(&self) -> ::std::option::Option<&crate::types::UserIdentityRoot> {
        self.root.as_ref()
    }
    /// <p>The type of entity that performed the action.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::UserIdentityType> {
        self.r#type.as_ref()
    }
}
impl UserIdentity {
    /// Creates a new builder-style object to manufacture [`UserIdentity`](crate::types::UserIdentity).
    pub fn builder() -> crate::types::builders::UserIdentityBuilder {
        crate::types::builders::UserIdentityBuilder::default()
    }
}

/// A builder for [`UserIdentity`](crate::types::UserIdentity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UserIdentityBuilder {
    pub(crate) assumed_role: ::std::option::Option<crate::types::AssumedRole>,
    pub(crate) aws_account: ::std::option::Option<crate::types::AwsAccount>,
    pub(crate) aws_service: ::std::option::Option<crate::types::AwsService>,
    pub(crate) federated_user: ::std::option::Option<crate::types::FederatedUser>,
    pub(crate) iam_user: ::std::option::Option<crate::types::IamUser>,
    pub(crate) root: ::std::option::Option<crate::types::UserIdentityRoot>,
    pub(crate) r#type: ::std::option::Option<crate::types::UserIdentityType>,
}
impl UserIdentityBuilder {
    /// <p>If the action was performed with temporary security credentials that were obtained using the AssumeRole operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub fn assumed_role(mut self, input: crate::types::AssumedRole) -> Self {
        self.assumed_role = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the action was performed with temporary security credentials that were obtained using the AssumeRole operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub fn set_assumed_role(mut self, input: ::std::option::Option<crate::types::AssumedRole>) -> Self {
        self.assumed_role = input;
        self
    }
    /// <p>If the action was performed with temporary security credentials that were obtained using the AssumeRole operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub fn get_assumed_role(&self) -> &::std::option::Option<crate::types::AssumedRole> {
        &self.assumed_role
    }
    /// <p>If the action was performed using the credentials for another Amazon Web Services account, the details of that account.</p>
    pub fn aws_account(mut self, input: crate::types::AwsAccount) -> Self {
        self.aws_account = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the action was performed using the credentials for another Amazon Web Services account, the details of that account.</p>
    pub fn set_aws_account(mut self, input: ::std::option::Option<crate::types::AwsAccount>) -> Self {
        self.aws_account = input;
        self
    }
    /// <p>If the action was performed using the credentials for another Amazon Web Services account, the details of that account.</p>
    pub fn get_aws_account(&self) -> &::std::option::Option<crate::types::AwsAccount> {
        &self.aws_account
    }
    /// <p>If the action was performed by an Amazon Web Services account that belongs to an Amazon Web Services service, the name of the service.</p>
    pub fn aws_service(mut self, input: crate::types::AwsService) -> Self {
        self.aws_service = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the action was performed by an Amazon Web Services account that belongs to an Amazon Web Services service, the name of the service.</p>
    pub fn set_aws_service(mut self, input: ::std::option::Option<crate::types::AwsService>) -> Self {
        self.aws_service = input;
        self
    }
    /// <p>If the action was performed by an Amazon Web Services account that belongs to an Amazon Web Services service, the name of the service.</p>
    pub fn get_aws_service(&self) -> &::std::option::Option<crate::types::AwsService> {
        &self.aws_service
    }
    /// <p>If the action was performed with temporary security credentials that were obtained using the GetFederationToken operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub fn federated_user(mut self, input: crate::types::FederatedUser) -> Self {
        self.federated_user = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the action was performed with temporary security credentials that were obtained using the GetFederationToken operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub fn set_federated_user(mut self, input: ::std::option::Option<crate::types::FederatedUser>) -> Self {
        self.federated_user = input;
        self
    }
    /// <p>If the action was performed with temporary security credentials that were obtained using the GetFederationToken operation of the Security Token Service (STS) API, the identifiers, session context, and other details about the identity.</p>
    pub fn get_federated_user(&self) -> &::std::option::Option<crate::types::FederatedUser> {
        &self.federated_user
    }
    /// <p>If the action was performed using the credentials for an Identity and Access Management (IAM) user, the name and other details about the user.</p>
    pub fn iam_user(mut self, input: crate::types::IamUser) -> Self {
        self.iam_user = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the action was performed using the credentials for an Identity and Access Management (IAM) user, the name and other details about the user.</p>
    pub fn set_iam_user(mut self, input: ::std::option::Option<crate::types::IamUser>) -> Self {
        self.iam_user = input;
        self
    }
    /// <p>If the action was performed using the credentials for an Identity and Access Management (IAM) user, the name and other details about the user.</p>
    pub fn get_iam_user(&self) -> &::std::option::Option<crate::types::IamUser> {
        &self.iam_user
    }
    /// <p>If the action was performed using the credentials for your Amazon Web Services account, the details of your account.</p>
    pub fn root(mut self, input: crate::types::UserIdentityRoot) -> Self {
        self.root = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the action was performed using the credentials for your Amazon Web Services account, the details of your account.</p>
    pub fn set_root(mut self, input: ::std::option::Option<crate::types::UserIdentityRoot>) -> Self {
        self.root = input;
        self
    }
    /// <p>If the action was performed using the credentials for your Amazon Web Services account, the details of your account.</p>
    pub fn get_root(&self) -> &::std::option::Option<crate::types::UserIdentityRoot> {
        &self.root
    }
    /// <p>The type of entity that performed the action.</p>
    pub fn r#type(mut self, input: crate::types::UserIdentityType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of entity that performed the action.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::UserIdentityType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of entity that performed the action.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::UserIdentityType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`UserIdentity`](crate::types::UserIdentity).
    pub fn build(self) -> crate::types::UserIdentity {
        crate::types::UserIdentity {
            assumed_role: self.assumed_role,
            aws_account: self.aws_account,
            aws_service: self.aws_service,
            federated_user: self.federated_user,
            iam_user: self.iam_user,
            root: self.root,
            r#type: self.r#type,
        }
    }
}
