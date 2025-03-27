package redis

//go:generate sh -c "rm -rf mocks && mkdir -p mocks"
//go:generate minimock -i UserCacheInterface -o ./mocks/ -s "_minimock.go"
