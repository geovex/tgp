package maplist

import "math/rand"

type MapList[K comparable, V any] struct {
	Data map[K][]V
}

func New[K comparable, V any]() *MapList[K, V] {
	return &MapList[K, V]{
		Data: map[K][]V{},
	}
}

func (m *MapList[K, V]) Add(key K, value V) {
	_, ok := m.Data[key]
	if !ok {
		m.Data[key] = []V{value}
	} else {
		m.Data[key] = append(m.Data[key], value)
	}
}

func (m *MapList[K, V]) GetRandom(key K) (val V, ok bool) {
	values_list, ok := m.Data[key]
	if !ok {
		return
	}
	values_list_len := len(values_list)
	if values_list_len == 0 {
		return
	}
	randIdx := rand.Intn(values_list_len)
	return values_list[randIdx], true
}
