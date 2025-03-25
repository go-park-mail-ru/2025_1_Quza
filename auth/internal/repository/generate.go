package repository

//go:generate sh -c "rm -rf mocks && mkdir -p mocks"
//go:generate minimock -i UserRepositoryInterface -o ./mocks/ -s "_minimock.go"
//go:generate minimock -i AccessPolicies -o ./mocks/ -s "_minimock.go"
