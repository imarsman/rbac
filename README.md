# RBAC - Role Based Access Control

A simple role-based authentication framework to allow for the use of a Casbin
policy and model configuration with verifications. The setup assumes that users
are defined outside of the policy and that they have a list of known roles that
can be tested against the policy.

The roles_test package gives an example of defining a model and policy, defining
the objects, actions, and roles (instead of users), and loading the model and
policy in the roles package. The tests show how to call the role check and give
an example of how to use a struct to define an object and action to test against
a list of roles, for instance, with HTTP middleware.